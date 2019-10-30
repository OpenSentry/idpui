package callbacks

import (
  "net/http"
  "golang.org/x/net/context"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gin-contrib/sessions"

  oidc "github.com/coreos/go-oidc"

  "github.com/charmixer/idpui/app"
  "github.com/charmixer/idpui/config"
)

func ExchangeAuthorizationCodeCallback(env *app.Environment) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(env.Constants.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ExchangeAuthorizationCodeCallback",
    })

    session := sessions.DefaultMany(c, env.Constants.SessionStoreKey)
    v := session.Get(env.Constants.SessionExchangeStateKey)
    if v == nil {
      log.WithFields(logrus.Fields{ "key":env.Constants.SessionExchangeStateKey }).Debug("Request not initiated by app. Hint: Missing session state")
      c.JSON(http.StatusBadRequest, gin.H{"error": "Request not initiated by idpui. Hint: Missing session state"})
      c.Abort()
      return;
    }
    sessionState := v.(string)

    log.WithFields(logrus.Fields{"fixme": 1}).Debug("Do we need to cleanup session state once consumed to ensure no reuse?")
    log.WithFields(logrus.Fields{"state": sessionState}).Debug("Exchange Authorization Code")

    requestState := c.Query("state")
    if requestState == "" {
      c.JSON(http.StatusBadRequest, gin.H{"error": "No state found. Hint: Missing state in query"})
      c.Abort()
      return;
    }

    if requestState != sessionState {
      c.JSON(http.StatusBadRequest, gin.H{"error": "Request did not originate from app. Hint: session state and request state differs"})
      c.Abort()
      return;
    }

    error := c.Query("error");
    if error != "" {
      errorHint := c.Query("error_hint")
      log.Debug(errorHint)
      c.JSON(http.StatusNotFound, gin.H{"error": error, "hint": errorHint})
      c.Abort()
      return;
    }

    code := c.Query("code")
    if code == "" {
      c.JSON(http.StatusBadRequest, gin.H{"error": "No code to exchange for an access token. Hint: Missing code in query"})
      c.Abort()
      return;
    }

    // Found a code try and exchange it for access token.
    token, err := env.OAuth2Delegator.Exchange(context.Background(), code)
    if err != nil {
      log.WithFields(logrus.Fields{"error": err.Error()}).Debug("Token exchange failed")
      c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    if token.Valid() == true {

      // Look into session for redirect_to using state
      var redirectTo string = config.GetString("oauth2.defaultRedirect")
      redirect := session.Get(sessionState)
      if redirect != nil {
        redirectTo = redirect.(string)
      }

      var idToken string
      __idToken, ok := token.Extra("id_token").(string)
      if ok == true {
        oidcConfig := &oidc.Config{
          ClientID: config.GetString("oauth2.client.id"),
        }

        verifier := env.Provider.Verifier(oidcConfig)

        _ /* idToken *oidc.IDToken*/, err = verifier.Verify(context.Background(), __idToken)
        if err != nil {
          log.Debug(err.Error())
          c.AbortWithStatus(http.StatusInternalServerError)
          return
        }
        idToken = __idToken
      }

      credentialsStore := sessions.DefaultMany(c, env.Constants.SessionCredentialsStoreKey)
      credentialsStore.Set(env.Constants.IdentityStoreKey, app.IdentityStore{
        Token: token,
        IdToken: idToken, // Save the raw Id token as we need it to hint logout.
      })
      err = credentialsStore.Save()
      if err == nil {

        session.Delete(sessionState) // Cleanup session redirect.
        err = session.Save()
        if err != nil {
          log.Debug("Failed to save session data: " + err.Error())
          c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to save application session data"})
          c.Abort()
          return
        }

        log.WithFields(logrus.Fields{"redirect_to": redirectTo}).Debug("Redirecting")
        c.Redirect(http.StatusFound, redirectTo)
        c.Abort()
        return;
      }

      log.Debug("Failed to save session data: " + err.Error())
      c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to save credentials session data"})
      c.Abort()
      return
    }

    // Deny by default.
    c.JSON(http.StatusUnauthorized, gin.H{"error": "Exchanged token was invalid. Hint: The timeout on the token might be to short?"})
    c.Abort()
    return
  }
  return gin.HandlerFunc(fn)
}
