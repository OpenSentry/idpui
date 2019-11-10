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

    error := c.Query("error");
    if error != "" {
      errorHint := c.Query("error_hint")
      c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": error, "hint": errorHint})
      return
    }

    code := c.Query("code")
    if code == "" {
      c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "No code to exchange for an access token. Hint: Missing code in query"})
      return
    }

    requestState := c.Query("state")
    if requestState == "" {
      log.Debug("Missing state in query")
      c.AbortWithStatus(http.StatusBadRequest)
      return
    }
    log = log.WithFields(logrus.Fields{ "query.state":requestState })

    log = log.WithFields(logrus.Fields{ "session.key":env.Constants.SessionExchangeStateKey })
    session := sessions.DefaultMany(c, env.Constants.SessionStoreKey)
    v := session.Get(env.Constants.SessionExchangeStateKey)
    if v == nil {
      log.Debug("Missing session state. Hint: Request was not initiated by idpui")
      c.AbortWithStatus(http.StatusBadRequest)
      return
    }
    sessionState := v.(string)
    log = log.WithFields(logrus.Fields{ "session.state":sessionState })

    // Require redirect_to registered to session exchange state
    v = session.Get(sessionState)
    if v == nil {
      log.Debug("Missing redirect_to in session")
      c.AbortWithStatus(http.StatusBadRequest)
      return
    }
    redirectTo := v.(string)
    log = log.WithFields(logrus.Fields{ "session.redirect_to":redirectTo })

    // Sanity check. Query state and session state must match. (CSRF on redirects)
    if requestState != sessionState {
      log.Debug("Request state and session state mismatch")
      c.AbortWithStatus(http.StatusBadRequest)
      return
    }

    // Found a code try and exchange it for access token.
    token, err := env.OAuth2Delegator.Exchange(context.Background(), code)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    if token.Valid() == true {

      __idToken, ok := token.Extra("id_token").(string)
      if ok == true {
        oidcConfig := &oidc.Config{ ClientID: config.GetString("oauth2.client.id") }
        verifier := env.Provider.Verifier(oidcConfig)
        idToken, err := verifier.Verify(context.Background(), __idToken)
        if err != nil {
          log.Debug(err.Error())
          c.AbortWithStatus(http.StatusInternalServerError)
          return
        }
        c.Set(env.Constants.ContextIdTokenKey, idToken)
        c.Set(env.Constants.ContextIdTokenHintKey, __idToken)
      }

      c.Set(env.Constants.ContextAccessTokenKey, token)
      log.WithFields(logrus.Fields{"redirect_to": redirectTo}).Debug("Redirecting")
      c.Redirect(http.StatusFound, redirectTo)
      c.Abort()
      return
    }

    // Deny by default.
    log.Debug("Exchanged token was invalid. Hint: The timeout on the token might be to short")
    c.AbortWithStatus(http.StatusUnauthorized)
    return
  }
  return gin.HandlerFunc(fn)
}
