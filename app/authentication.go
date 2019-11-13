package app

import (
  "strings"
  "net/http"
  "net/url"
  "golang.org/x/net/context"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gin-contrib/sessions"
  "golang.org/x/oauth2"
  oidc "github.com/coreos/go-oidc"

  "github.com/charmixer/idpui/config"
  idp "github.com/charmixer/idp/client"

  bulky "github.com/charmixer/bulky/client"
)

// # Authentication and Authorization
// ## QTNA - Questions that need answering before granting access to a protected resource
// 1. Is the user or client authenticated? Answered by the process of obtaining an access token.
// 2. Is the access token expired?
// 3. Is the access token granted the required scopes?
// 4. Is the user or client giving the grants in the access token authorized to operate the scopes granted?
// 5. Is the access token revoked?

func ConfigureOAuth2(env *Environment, clientId string, clientSecret string, redirectUrl string, Scopes ...string) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(env.Constants.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ConfigureOAuth2",
    })

    if clientId == "" {
      log.Debug("Missing client_id")
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    if clientSecret == "" {
      log.Debug("Missing client_secret")
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    endpoint := env.Provider.Endpoint()
    endpoint.AuthStyle = 2 // Force basic secret, so token exchange does not auto to post which we did not allow.

    config := &oauth2.Config{
      ClientID:     clientId,
      ClientSecret: clientSecret,
      Endpoint:     endpoint,
      RedirectURL:  redirectUrl,
      Scopes:       Scopes,
    }

    c.Set(env.Constants.ContextOAuth2ConfigKey, config)
    c.Next()
  }
  return gin.HandlerFunc(fn)
}

func RequestAccessToken(env *Environment, oauth2Delegator *oauth2.Config) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(env.Constants.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "RequestAccessToken",
    })

    error := c.Query("error");
    if error != "" {
      errorHint := c.Query("error_hint")
      c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": error, "hint": errorHint})
      return
    }

    if oauth2Delegator == nil {
      log.Debug("No OAuth2 config")
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    code := c.Query("code")
    if code != "" {

      // Try and exchange code for access token to use.
      requestState := c.Query("state")
      if requestState == "" {
        log.Debug("Missing state in query")
        c.AbortWithStatus(http.StatusBadRequest)
        return
      }
      log = log.WithFields(logrus.Fields{ "state":requestState })

      valid, err := ValidateRequestStateWithRedirectCsrfSession(env, c, env.Constants.SessionExchangeStateKey, requestState)
      if err != nil {
        log.Debug(err.Error())
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }

      if valid == false {
        log.Debug("Request state invalid")
        c.AbortWithStatus(http.StatusBadRequest)
        return
      }

      // Require redirect_to registered to session exchange state
      redirectTo, err := FetchRedirectToForRedirectCsrfSession(env, c, env.Constants.SessionExchangeStateKey)
      if err != nil {
        log.Debug(err.Error())
        c.AbortWithStatus(http.StatusBadRequest)
        return
      }
      log = log.WithFields(logrus.Fields{ "session.redirect_to":redirectTo })

      // Found a code try and exchange it for access token.
      token, err := oauth2Delegator.Exchange(context.Background(), code)
      if err != nil {
        log.Debug(err.Error())
        // FIXME: Maybe we should redirect back reboot the process. Since the access token was not aquired.
        c.AbortWithStatus(http.StatusBadRequest)
        return
      }

      if token.Valid() == true {

        idpClient := idp.NewIdpClientWithUserAccessToken(oauth2Delegator, token)

        __idToken, ok := token.Extra("id_token").(string)
        if ok == true {

          // Found id_token, verify it.
          oidcConfig := &oidc.Config{ ClientID:oauth2Delegator.ClientID }
          verifier := env.Provider.Verifier(oidcConfig)
          idToken, err := verifier.Verify(context.Background(), __idToken)
          if err != nil {
            log.Debug(err.Error())
            c.AbortWithStatus(http.StatusInternalServerError)
            return
          }

          // Id token found lookup identity.
          identityRequest := []idp.ReadHumansRequest{ {Id: idToken.Subject} }
          status, responses, err := idp.ReadHumans(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.humans.collection"), identityRequest)
          if err != nil {
            log.Debug(err.Error())
            c.AbortWithStatus(http.StatusInternalServerError)
            return
          }

          if status != http.StatusOK {
            log.WithFields(logrus.Fields{ "status":status }).Debug("Humans read failed")
            c.AbortWithStatus(http.StatusInternalServerError)
            return
          }

          var resp idp.ReadHumansResponse
          reqStatus, reqErrors := bulky.Unmarshal(0, responses, &resp)
          if len(reqErrors) > 0 {
            log.Debug(reqErrors)
            log.Debug("Humans unmarshal failed")
            c.AbortWithStatus(http.StatusInternalServerError)
            return
          }

          if reqStatus == 200 {
            c.Set(env.Constants.ContextIdentityKey, resp[0])
            c.Set(env.Constants.ContextIdTokenKey, idToken)
            c.Set(env.Constants.ContextIdTokenHintKey, __idToken)
          }

        }

        c.Set(env.Constants.ContextAccessTokenKey, token)

        c.Set(env.Constants.IdpClientKey, idpClient)
        c.Next()
        return
      }

    }

    // Unauthorized, request a code
    initUrl, err := StartAuthenticationSession(env, oauth2Delegator, c)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }
    c.Redirect(http.StatusFound, initUrl.String())
    c.Abort()
    return
  }
  return gin.HandlerFunc(fn)
}

func OAuth2Config(env *Environment, c *gin.Context) (*oauth2.Config) {
  t, exists := c.Get(env.Constants.ContextOAuth2ConfigKey)
  if exists == true {
    return t.(*oauth2.Config)
  }
  return nil
}

func IdpClientWithToken(env *Environment, c *gin.Context) (*idp.IdpClient) {
  t, exists := c.Get(env.Constants.IdpClientKey)
  if exists == true {
    return t.(*idp.IdpClient)
  }
  return nil
}

func GetIdentity(env *Environment, c *gin.Context) *idp.Human {
  identity, exists := c.Get(env.Constants.ContextIdentityKey)
  if exists == true {
    human := identity.(idp.Human)
    return &human
  }
  return nil
}

func createPostRedirectUri(requestedUrl string) (redirectTo string, err error) {

  loginUrl, err := url.Parse(config.GetString("idpui.public.endpoints.login"))
  if err != nil {
    return "", err
  }

  // Redirect to after successful authentication
  wantUrl, err := url.Parse(requestedUrl)
  if err != nil {
    return "", err
  }

  // Clean query params before comparing
  q := url.Values{}

  loginUrl.RawQuery = q.Encode()
  wantUrl.RawQuery = q.Encode()

  if strings.EqualFold(wantUrl.String(), loginUrl.String()) {
    redirectTo = config.GetString("idpui.public.endpoints.root") // Do not allow landing login controller after authentication as it will create an inf. loop.
  } else {
    redirectTo = requestedUrl
  }

  return redirectTo, nil
}

func StartAuthenticationSession(env *Environment, oauth2Delegator *oauth2.Config, c *gin.Context) (authorizationCodeUrl *url.URL, err error) {
  var state string

  redirectTo, err := createPostRedirectUri(c.Request.RequestURI)
  if err != nil {
    return nil, err
  }

  // Always generate a new authentication session state
  session := sessions.DefaultMany(c, env.Constants.SessionRedirectCsrfStoreKey)

  // Create random bytes that are based64 encoded to prevent character problems with the session store.
  // The base 64 means that more than 64 bytes are stored! Which can cause "securecookie: the value is too long"
  // To prevent this we need to use a filesystem store instead of broser cookies.
  state, err = CreateRandomStringWithNumberOfBytes(32);
  if err != nil {
    return nil, err
  }

  session.Set(env.Constants.SessionExchangeStateKey, state)
  session.Set(state, redirectTo)
  err = session.Save()
  if err != nil {
    return nil, err
  }

  authUrl := oauth2Delegator.AuthCodeURL(state)
  authorizationCodeUrl, err = url.Parse(authUrl)
  if err != nil {
    return nil, err
  }

  return authorizationCodeUrl, err
}

func AccessToken(env *Environment, c *gin.Context) (*oauth2.Token) {
  t, exists := c.Get(env.Constants.ContextAccessTokenKey)
  if exists == true {
    return t.(*oauth2.Token)
  }
  return nil
}

func IdToken(env *Environment, c *gin.Context) (*oidc.IDToken) {
  t, exists := c.Get(env.Constants.ContextIdTokenKey)
  if exists == true {
    return t.(*oidc.IDToken)
  }
  return nil
}

func IdTokenHint(env *Environment, c *gin.Context) (string) {
  t, exists := c.Get(env.Constants.ContextIdTokenHintKey)
  if exists == true {
    return t.(string)
  }
  return ""
}