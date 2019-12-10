package app

import (
  //"fmt"
  "net/http"
  "net/url"
  "github.com/gin-gonic/gin"
  "github.com/sirupsen/logrus"
  oidc "github.com/coreos/go-oidc"
  "golang.org/x/oauth2"
  "golang.org/x/net/context"

  "github.com/opensentry/idpui/config"
  idp "github.com/opensentry/idp/client"

  bulky "github.com/charmixer/bulky/client"
)

func RequireScopes(env *Environment, requiredScopes ...string) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(env.Constants.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "RequireScopes",
    })

    if len(requiredScopes) <= 0 {
      log.Debug("'Missing required scopes'")
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    _requiredScopes := FetchRequiredScopes(env, c)
    _requiredScopes = append(_requiredScopes, requiredScopes...)

    c.Set(env.Constants.ContextRequiredScopesKey, _requiredScopes)
    c.Next()
    return
  }
  return gin.HandlerFunc(fn)
}

func FetchRequiredScopes(env *Environment, c *gin.Context) (requiredScopes []string) {
  t, exists := c.Get(env.Constants.ContextRequiredScopesKey)
  if exists == true {
    return t.([]string)
  }
  return nil
}

func UsePrecalculatedStateFromQuery(env *Environment, queryParamKey string) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(env.Constants.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "UsePrecalculatedState",
    })

    u, err := url.Parse(c.Request.RequestURI)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }
    q := u.Query()
    state := q.Get(queryParamKey)
    if state != "" {
      c.Set(env.Constants.ContextPrecalculatedStateKey, state)
    }
    c.Next()
    return
  }
  return gin.HandlerFunc(fn)
}

func FetchPrecalculatedState(env *Environment, c *gin.Context) (precaluclatedState string) {
  t, exists := c.Get(env.Constants.ContextPrecalculatedStateKey)
  if exists == true {
    return t.(string)
  }
  return ""
}


func ConfigureOauth2(env *Environment) gin.HandlerFunc {
  fn := func(c *gin.Context) {
    log := c.MustGet(env.Constants.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ConfigureOauth2",
    })

    requiredScopes := FetchRequiredScopes(env, c)
    if requiredScopes == nil {
      log.Debug("Missing required scopes")
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    // Setup the OAuth2 config for the request.
    endpoint := env.Provider.Endpoint()
    endpoint.AuthStyle = 2 // Force basic secret, so token exchange does not auto to post which we did not allow.

    exchangeRedirectUrl, err := createAuthorizationCodeExchangeUrl(c.Request)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    var oauth2Config *oauth2.Config = &oauth2.Config{
      ClientID: env.ClientId,
      ClientSecret: env.ClientSecret,
      Endpoint: endpoint,
      RedirectURL: exchangeRedirectUrl,
      Scopes: requiredScopes,
    }

    if oauth2Config == nil {
      log.Debug("Create oauth2 config failed")
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    c.Set(env.Constants.ContextOAuth2ConfigKey, oauth2Config) // Save as pointer.
    c.Next()
    return
  }
  return gin.HandlerFunc(fn)
}

func FetchOAuth2Config(env *Environment, c *gin.Context) (*oauth2.Config) {
  t, exists := c.Get(env.Constants.ContextOAuth2ConfigKey) // Read as pointer
  if exists == true {
    return t.(*oauth2.Config)
  }
  return nil
}

// This implements authorization code flow exchange controller functionality to prevent session storage on normal callback endpoints.
func RequestTokenUsingAuthorizationCode(env *Environment) gin.HandlerFunc {
  fn := func(c *gin.Context) {
    log := c.MustGet(env.Constants.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "RequestTokenUsingAuthorizationCode",
    })

    error := c.Query("error"); // Hydra specific error handling
    if error != "" {
      c.AbortWithStatus(http.StatusBadRequest)
      return
    }

    oauth2Config := FetchOAuth2Config(env, c)
    if oauth2Config == nil {
      log.Debug("Missing oauth2 config. Hint: Oauth2 config is missing from context. Did you call ConfigureOauth2 before calling RequestTokenUsingAuthorizationCode?")
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    code := c.Query("code")
    if code == "" {
      // Unauthorized, request an access token for required scopes only using authorization code flow.
      // TODO: Add pkce

      idTokenHint := IdTokenHint(env, c)

      // Use precalculated state iff present
      state := FetchPrecalculatedState(env, c)

      initUrl, err := StartAuthenticationSession(env, c, oauth2Config, idTokenHint, state)
      if err != nil {
        log.Debug(err.Error())
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }

      // This is not allowed by ORY Hydra even though the url (without params) is registered to the client
      /*emailChallenge := c.Query("email_challenge")
      if emailChallenge != "" {
        q := initUrl.Query()

        redirectUri := q.Get("redirect_uri")
        if redirectUri != "" {
          _redirect, err := url.Parse(redirectUri)
          if err != nil {
            log.Debug(err.Error())
            c.AbortWithStatus(http.StatusInternalServerError)
            return
          }

          rq := _redirect.Query()
          rq.Add("email_challenge", emailChallenge)
          _redirect.RawQuery = rq.Encode()
          q.Set("redirect_uri", _redirect.String())
          initUrl.RawQuery = q.Encode()
        }

      }*/

      c.Redirect(http.StatusFound, initUrl.String())
      c.Abort()
      return
    }

    // We recived a code request, try and exchange it for a token.

    requestState := c.Query("state")
    if requestState == "" {
      log.Debug("Missing state in query")
      c.AbortWithStatus(http.StatusBadRequest)
      return
    }
    log = log.WithFields(logrus.Fields{ "state":requestState })

    valid := ValidateSessionState(env, c, requestState)
    if valid == false {
      log.Debug("Request state invalid")
      c.AbortWithStatus(http.StatusBadRequest)
      return
    }

    // Require redirect_to registered to session exchange state
    redirectTo, exists := FetchSessionRedirect(env, c, requestState)
    if exists == false {
      log.Debug("Session redirect not found")
      c.AbortWithStatus(http.StatusBadRequest)
      return
    }
    log = log.WithFields(logrus.Fields{ "session.redirect_to":redirectTo })

    token, err := oauth2Config.Exchange(context.Background(), code)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusBadRequest) // FIXME: Maybe we should redirect back reboot the process. Since the access token was not aquired.
      return
    }

    if token.Valid() == false {
      c.AbortWithStatus(http.StatusForbidden)
      return
    }

    // Optional extract IdToken iff present.
    idToken, idTokenHint, err := fetchIdTokenFromAccessToken(env, oauth2Config, token)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusBadRequest)
      return
    }

    if idToken != nil {
      c.Set(env.Constants.ContextIdTokenKey, idToken)
    }

    if idTokenHint != "" {
      c.Set(env.Constants.ContextIdTokenHintKey, idTokenHint)
    }

    c.Set(env.Constants.ContextAccessTokenKey, token)
    c.Next()
    return
  }
  return gin.HandlerFunc(fn)
}

func fetchIdTokenFromAccessToken(env *Environment, oauth2Config *oauth2.Config, token *oauth2.Token) (idToken *oidc.IDToken, idTokenHint string, err error) {
  idTokenHint, ok := token.Extra("id_token").(string)
  if ok != true {
    return nil, "", nil
  }

  // Found id_token, verify it.
  oidcConfig := &oidc.Config{ ClientID:oauth2Config.ClientID }
  verifier := env.Provider.Verifier(oidcConfig)
  idToken, err = verifier.Verify(context.Background(), idTokenHint)
  if err != nil {
    return nil, "", err
  }

  return idToken, idTokenHint, nil
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


func RequireIdentity(env *Environment) gin.HandlerFunc {
  fn := func(c *gin.Context) {
    log := c.MustGet(env.Constants.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "RequireIdentity",
    })

    token := AccessToken(env, c)
    if token == nil {
      log.Debug("Missing access token. Hint: Access token is missing from context. Did you call RequestTokenUsingAuthorizationCode called before calling RequireIdentity?")
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    idToken := IdToken(env, c)
    if idToken == nil {
      log.Debug("Missing id token. Hint: Id token is missing from context. Did you call RequireScopes(openid) and RequestTokenUsingAuthorizationCode called before calling RequireIdentity?")
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    oauth2Config := FetchOAuth2Config(env, c)
    if oauth2Config == nil {
      log.Debug("Missing oauth2 config. Hint: Oauth2 config is missing from context. Did you call ConfigureOauth2 before calling RequireIdentity?")
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    // FIXME: This should be defined on application start up and verified and stored in a map to use here.
    idpHumansUrl := config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.humans.collection")

    // Id token found lookup identity.
    idpClient := idp.NewIdpClientWithUserAccessToken(oauth2Config, token)
    humanRequest := idp.ReadHumansRequest{ Id:idToken.Subject }
    status, responses, err := idp.ReadHumans(idpClient, idpHumansUrl, []idp.ReadHumansRequest{ humanRequest })
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    if status != http.StatusOK {
      log.WithFields(logrus.Fields{ "id":humanRequest.Id, "status":status }).Debug("Humans read failed")
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
      human := resp[0]
      if human.Id == "" {
        log.WithFields(logrus.Fields{ "id":humanRequest.Id }).Debug("Human not found. Hint: Idp did not return an id for the human")
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }
      c.Set(env.Constants.ContextIdentityKey, resp[0])
      c.Next()
      return
    }

    // Deny
    log.WithFields(logrus.Fields{ "id":humanRequest.Id }).Debug("Human not found")
    c.AbortWithStatus(http.StatusNotFound)
    return
  }
  return gin.HandlerFunc(fn)
}

func GetIdentity(env *Environment, c *gin.Context) *idp.Human {
  identity, exists := c.Get(env.Constants.ContextIdentityKey)
  if exists == true {
    human := identity.(idp.Human)
    return &human
  }
  return nil
}
