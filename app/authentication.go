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
// Gin middleware to secure idp fe endpoints using oauth2.
//
// ## QTNA - Questions that need answering before granting access to a protected resource
// 1. Is the user or client authenticated? Answered by the process of obtaining an access token.
// 2. Is the access token expired?
// 3. Is the access token granted the required scopes?
// 4. Is the user or client giving the grants in the access token authorized to operate the scopes granted?
// 5. Is the access token revoked?

func AuthenticationRequired(env *Environment) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(env.Constants.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "AuthenticationRequired",
    })

    var err error
    var token *oauth2.Token
    var idToken *oidc.IDToken
    var __idToken string

    credentialsStore := sessions.DefaultMany(c, env.Constants.SessionCredentialsStoreKey)
    obj := credentialsStore.Get(env.Constants.IdentityStoreKey)
    if obj != nil {
      idStore := obj.(*IdentityStore)
      if idStore != nil {
        log.WithFields(logrus.Fields{"authorization": "session"})
        token = idStore.Token
        __idToken = idStore.IdToken
      }
    }

    if token != nil {

      log.Debug("Access token found")

      tokenSource := env.OAuth2Delegator.TokenSource(oauth2.NoContext, token)
      newToken, err := tokenSource.Token()
      if err != nil {
        log.Debug(err.Error())
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }

      if newToken.AccessToken != token.AccessToken {
        log.Debug("Access token refreshed")
        token = newToken
      }

      // See #2 of QTNA
      // https://godoc.org/golang.org/x/oauth2#Token.Valid
      if token.Valid() == true {

        log.Debug("Access token valid")

        if __idToken != "" {
          oidcConfig := &oidc.Config{ ClientID: config.GetString("oauth2.client.id") }
          verifier := env.Provider.Verifier(oidcConfig)
          idToken, err = verifier.Verify(context.Background(), __idToken)
          if err != nil {
            log.Debug(err.Error())
            c.AbortWithStatus(http.StatusInternalServerError)
            return
          }
        }

        if idToken == nil {
          c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing id_token. Hint: Access token did not contain an id_token. Are you missing openid scope?"})
          return
        }

        // See #5 of QTNA
        log.WithFields(logrus.Fields{"fixme": 1, "qtna": 5}).Debug("Missing check against token-revoked-list to check if token is revoked") // Call token revoked list to check if token is revoked.

        log.Debug("Authenticated")
        c.Set(env.Constants.ContextAccessTokenKey, token)
        c.Set(env.Constants.ContextIdTokenKey, idToken)
        c.Set(env.Constants.ContextIdTokenHintKey, __idToken)
        c.Next()
        return
      }

    }

    // Deny by default
    log.Debug("Unauthorized")

    initUrl, err := StartAuthenticationSession(env, c, log)
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

// Use this handler as middleware to enable gateway functions in controllers
func RequireIdentity(env *Environment) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    var idToken *oidc.IDToken = IdToken(env, c)
    if idToken == nil {
      c.AbortWithStatus(http.StatusUnauthorized)
      return
    }

    var accessToken *oauth2.Token = AccessToken(env, c)
    if accessToken == nil {
      c.AbortWithStatus(http.StatusForbidden)
      return
    }

    idpClient := idp.NewIdpClientWithUserAccessToken(env.OAuth2Delegator, accessToken)

    // Look up profile information for user.
    identityRequest := []idp.ReadHumansRequest{ {Id: idToken.Subject} }
    status, responses, err := idp.ReadHumans(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.humans.collection"), identityRequest)
    if err != nil {
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    if status == http.StatusOK {

      var resp idp.ReadHumansResponse
      reqStatus, reqErrors := bulky.Unmarshal(0, responses, &resp)
      if len(reqErrors) > 0 {
        logrus.Debug(reqErrors)
      } else {

        if reqStatus == 200 {
          c.Set(env.Constants.ContextIdentityKey, resp[0])
          c.Next()
          return
        }

      }

    }

    // Deny by default
    c.AbortWithStatus(http.StatusForbidden)
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

func StartAuthenticationSession(env *Environment, c *gin.Context, log *logrus.Entry) (*url.URL, error) {
  var state string
  var err error

  log = log.WithFields(logrus.Fields{
    "func": "StartAuthenticationSession",
  })

  redirectTo, err := createPostRedirectUri(c.Request.RequestURI)
  if err != nil {
    return nil, err
  }

  // Always generate a new authentication session state
  session := sessions.DefaultMany(c, env.Constants.SessionStoreKey)

  // Create random bytes that are based64 encoded to prevent character problems with the session store.
  // The base 64 means that more than 64 bytes are stored! Which can cause "securecookie: the value is too long"
  // To prevent this we need to use a filesystem store instead of broser cookies.
  state, err = CreateRandomStringWithNumberOfBytes(32);
  if err != nil {
    log.Debug(err.Error())
    return nil, err
  }

  session.Set(env.Constants.SessionExchangeStateKey, state)
  session.Set(state, redirectTo)
  err = session.Save()
  if err != nil {
    log.Debug(err.Error())
    return nil, err
  }

  logSession := log.WithFields(logrus.Fields{
    "redirect_to": redirectTo,
    "state": state,
  })
  logSession.Debug("Started session")
  authUrl := env.OAuth2Delegator.AuthCodeURL(state)
  u, err := url.Parse(authUrl)
  return u, err
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