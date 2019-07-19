package main

import (
  "errors"
  "strings"
  "fmt"
  "net/url"
  "net/http"
  //"encoding/base64"
  "encoding/gob"
  //"crypto/rand"
  //"reflect"

  "golang.org/x/net/context"
  "golang.org/x/oauth2"
  "golang.org/x/oauth2/clientcredentials"

  "github.com/gin-gonic/gin"
  "github.com/gin-contrib/sessions"
  "github.com/gin-contrib/sessions/cookie"
  "github.com/gorilla/csrf"
  "github.com/gwatts/gin-adapter"
  "github.com/atarantini/ginrequestid"

  oidc "github.com/coreos/go-oidc"

  "golang-idp-fe/config"
  "golang-idp-fe/environment"
  "golang-idp-fe/controllers"
  "golang-idp-fe/gateway/idpbe"
  //"golang-idp-fe/gateway/cpbe"
)

func init() {
  config.InitConfigurations()
  gob.Register(&oauth2.Token{}) // This is required to make session in idp-fe able to persist tokens.
  gob.Register(&oidc.IDToken{})
  gob.Register(&idpbe.Profile{})
  gob.Register(make(map[string][]string))
}

func main() {

  provider, err := oidc.NewProvider(context.Background(), config.Hydra.Url + "/")
  if err != nil {
    fmt.Println(err)
    return
  }

  // IdpFe needs to be able to act as an App using its client_id to bootstrap Authorization Code flow
  // Eg. Users accessing /me directly from browser.
  hydraConfig := &oauth2.Config{
    ClientID:     config.IdpFe.ClientId,
    ClientSecret: config.IdpFe.ClientSecret,
    Endpoint:     provider.Endpoint(),
    RedirectURL:  config.IdpFe.PublicCallbackUrl,
    Scopes:       []string{"openid", "offline"},
  }

  // IdpFe needs to be able as an App using client_id to access IdpBe endpoints. Using client credentials flow
  idpbeConfig := &clientcredentials.Config{
    ClientID:  config.IdpFe.ClientId,
    ClientSecret: config.IdpFe.ClientSecret,
    TokenURL: provider.Endpoint().TokenURL,
    Scopes: config.IdpFe.RequiredScopes,
    EndpointParams: url.Values{"audience": {"idpbe"}},
    AuthStyle: 2, // https://godoc.org/golang.org/x/oauth2#AuthStyle
  }

  cpbeConfig := &clientcredentials.Config{
    ClientID:  config.IdpFe.ClientId,
    ClientSecret: config.IdpFe.ClientSecret,
    TokenURL: provider.Endpoint().TokenURL,
    Scopes: config.IdpFe.RequiredScopes,
    EndpointParams: url.Values{"audience": {"cpbe"}},
    AuthStyle: 2, // https://godoc.org/golang.org/x/oauth2#AuthStyle
  }

  // Setup app state variables. Can be used in handler functions by doing closures see exchangeAuthorizationCodeCallback
  env := &environment.State{
    Provider: provider,
    HydraConfig: hydraConfig,
    IdpBeConfig: idpbeConfig,
    CpBeConfig: cpbeConfig,
  }

   r := gin.Default()
   r.Use(ginrequestid.RequestId())

   store := cookie.NewStore(config.IdpFe.SessionAuthKey)
   // Ref: https://godoc.org/github.com/gin-gonic/contrib/sessions#Options
   store.Options(sessions.Options{
       MaxAge: 86400,
       Path: "/",
       Secure: true,
       HttpOnly: true,
   })
   r.Use(sessions.Sessions(environment.SessionStoreKey, store))

   // Use CSRF on all idp-fe forms.
   adapterCSRF := adapter.Wrap(csrf.Protect([]byte(config.IdpFe.CsrfAuthKey), csrf.Secure(true)))
   // r.Use(adapterCSRF) // Do not use this as it will make csrf tokens for public files aswell which is just extra data going over the wire, no need for that.

   r.Static("/public", "public")
   r.LoadHTMLGlob("views/*")

   // Setup routes to use, this defines log for debug log
   routes := map[string]environment.Route{
     "/": environment.Route{
        URL: "/",
        LogId: "idpfe://",
     },
     "/authenticate": environment.Route{
       URL: "/authenticate",
       LogId: "idpfe://authenticate",
     },
     "/logout": environment.Route{
       URL: "/logout",
       LogId: "idpfe://logout",
     },
     "/session/logout": environment.Route{
       URL: "/session/logout",
       LogId: "idpfe://session/logout",
     },
     "/register": environment.Route{
       URL: "/register",
       LogId: "idpfe://register",
     },
     "/recover": environment.Route{
       URL: "/recover",
       LogId: "idpfe://recover",
     },
     "/callback": environment.Route{
       URL: "/callback",
       LogId: "idpfe://callback",
     },
     "/me": environment.Route{
       URL: "/me",
       LogId: "idpfe://me",
     },
     "/consent": environment.Route{
       URL: "/consent",
       LogId: "idpfe://consent",
     },
   }

   ep := r.Group("/")
   ep.Use(adapterCSRF)
   {
     ep.GET(routes["/"].URL, controllers.ShowAuthentication(env, routes["/"]))
     ep.GET(routes["/authenticate"].URL, controllers.ShowAuthentication(env, routes["/authenticate"]))
     ep.POST(routes["/authenticate"].URL, controllers.SubmitAuthentication(env, routes["/authenticate"]))

     ep.GET(routes["/logout"].URL, AuthenticationAndAuthorizationRequired(env, routes["/logout"], "openid"), controllers.ShowLogout(env, routes["/logout"]))
     ep.POST(routes["/logout"].URL, AuthenticationAndAuthorizationRequired(env, routes["/logout"], "openid"), controllers.SubmitLogout(env, routes["/logout"]))

     ep.GET(routes["/session/logout"].URL, controllers.ShowLogoutSession(env, routes["/session/logout"])) // These does not require authentication as its like doing delete in browser on cookies.
     ep.POST(routes["/session/logout"].URL, controllers.SubmitLogoutSession(env, routes["/session/logout"]))

     ep.GET(routes["/register"].URL, controllers.ShowRegistration(env, routes["/register"]))
     ep.POST(routes["/register"].URL, controllers.SubmitRegistration(env, routes["/register"]))

     ep.GET(routes["/recover"].URL, controllers.ShowRecover(env, routes["/recover"]))
     ep.POST(routes["/recover"].URL, controllers.SubmitRecover(env, routes["/recover"]))

     ep.GET(routes["/callback"].URL, controllers.ExchangeAuthorizationCodeCallback(env, routes["/callback"])) // token exhange endpoint.

     ep.GET(routes["/me"].URL, AuthenticationAndAuthorizationRequired(env, routes["/me"], "openid"), controllers.ShowProfile(env, routes["/me"]))

     ep.GET(routes["/consent"].URL, AuthenticationAndAuthorizationRequired(env, routes["/consent"], "openid"), controllers.ShowConsent(env, routes["/consent"]))
     ep.POST(routes["/consent"].URL, AuthenticationAndAuthorizationRequired(env, routes["/consent"], "openid"), controllers.SubmitConsent(env, routes["/consent"]))
   }

   r.RunTLS(":" + config.Self.Port, "/srv/certs/idpfe-cert.pem", "/srv/certs/idpfe-key.pem")
}

// # Authentication and Authorization
// Gin middleware to secure idp fe endpoints using oauth2.
//
// ## QTNA - Questions that need answering before granting access to a protected resource
// 1. Is the user or client authenticated? Answered by the process of obtaining an access token.
// 2. Is the access token expired?
// 3. Is the access token granted the required scopes?
// 4. Is the user or client giving the grants in the access token authorized to operate the scopes granted?
// 5. Is the access token revoked?
func AuthenticationAndAuthorizationRequired(env *environment.State, route environment.Route, requiredScopes ...string) gin.HandlerFunc {
  fn := func(c *gin.Context) {
    var requestId string = c.MustGet(environment.RequestIdKey).(string)
    environment.DebugLog(route.LogId, "AuthenticationAndAuthorizationRequired", "", requestId)

    // Authentication
    token, err := authenticationRequired(env, c, route)
    if err != nil {
      // Require authentication to access resources. Init oauth2 Authorization code flow with idpfe as the client.
      environment.DebugLog(route.LogId, "AuthenticationAndAuthorizationRequired", "Error: " + err.Error(), requestId)
      initUrl, err := controllers.StartAuthentication(env, c, route)
      if err != nil {
        environment.DebugLog(route.LogId, "AuthenticationAndAuthorizationRequired", "Error: " + err.Error(), requestId)
        c.HTML(http.StatusInternalServerError, "", gin.H{"error": err.Error()})
        c.Abort()
        return
      }
      c.Redirect(http.StatusFound, initUrl.String())
      c.Abort()
      return
    }
    c.Set(environment.AccessTokenKey, token) // Authenticated, so use it forward.

    // Authorization
    grantedScopes, err := authorizationRequired(env, c, route, requiredScopes)
    if err != nil {
      environment.DebugLog(route.LogId, "AuthenticationAndAuthorizationRequired", "Error: " + err.Error(), requestId)
      c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
      c.Abort()
      return
    }
    fmt.Println(grantedScopes)

    // FIXME: Find IdToken for access token.
    idToken := &oauth2.Token{}
    c.Set(environment.IdTokenKey, idToken) // Authorized

    c.Next() // Authentication and authorization successful, continue.
    return
  }
  return gin.HandlerFunc(fn)
}

func authenticationRequired(env *environment.State, c *gin.Context, route environment.Route) (*oauth2.Token, error) {
  var requestId string = c.MustGet(environment.RequestIdKey).(string)
  environment.DebugLog(route.LogId, "authenticationRequired", "Checking Authorization: Bearer <token> in request", requestId)

  session := sessions.Default(c)

  var token *oauth2.Token
  auth := c.Request.Header.Get("Authorization")
  split := strings.SplitN(auth, " ", 2)
  if len(split) == 2 || strings.EqualFold(split[0], "bearer") {
    environment.DebugLog(route.LogId, "authenticationRequired", "Authorization: Bearer <token> found for request.", requestId)
    token = &oauth2.Token{
      AccessToken: split[1],
      TokenType: split[0],
    }
  } else {
    environment.DebugLog(route.LogId, "authenticationRequired", "Checking Session <token> in request", requestId)
    v := session.Get(environment.SessionTokenKey)
    if v != nil {
      token = v.(*oauth2.Token)
      environment.DebugLog(route.LogId, "authenticationRequired", "Session <token> found in request", requestId)
    }
  }

  tokenSource := env.HydraConfig.TokenSource(oauth2.NoContext, token)
  newToken, err := tokenSource.Token()
  if err != nil {
    return nil, err
  }

  if newToken.AccessToken != token.AccessToken {
    environment.DebugLog(route.LogId, "authenticationRequired", "Token was refresed. Updated session token to match new token", requestId)
    session.Set(environment.SessionTokenKey, newToken)
    session.Save()
    token = newToken
  }
/*
  client := oauth2.NewClient(oauth2.NoContext, tokenSource)
  resp, err := client.Get(url)*/

  // See #2 of QTNA
  // https://godoc.org/golang.org/x/oauth2#Token.Valid
  if token.Valid() == true {
    environment.DebugLog(route.LogId, "authenticationRequired", "Valid access token", requestId)

    // See #5 of QTNA
    // FIXME: Call token revoked list to check if token is revoked.
    environment.DebugLog(route.LogId, "authenticationRequired", "Missing implementation of QTNA #5 - Is the access token revoked?", requestId)

    return token, nil
  }

  // Deny by default
  environment.DebugLog(route.LogId, "authenticationRequired", "Missing or invalid access token", requestId)
  return nil, errors.New("Missing or invalid access token")
}

func authorizationRequired(env *environment.State, c *gin.Context, route environment.Route, requiredScopes []string) ([]string, error) {
  var requestId string = c.MustGet(environment.RequestIdKey).(string)
  environment.DebugLog(route.LogId, "authorizationRequired", "Checking required scopes for request", requestId)

  var grantedScopes []string

  // See #3 of QTNA
  environment.DebugLog(route.LogId, "authorizationRequired", "Missing implementation of QTNA #3 - Is the access token granted the required scopes?", requestId)
  /*cpbeClient := cpbe.NewCpBeClient(env.CpBeConfig)
  grantedScopes, err := cpbe.IsRequiredScopesGrantedForToken(config.CpBe.AuthorizationsUrl, cpbeClient, requiredScopes)
  if err != nil {
    return nil, err
  }*/

  // See #4 of QTNA
  // FIXME: Is user who granted the scopes allow to use the scopes (check cpbe model for what user is allowed to do.)
  environment.DebugLog(route.LogId, "authorizationRequired", "Missing implementation of QTNA #4 - Is the user or client giving the grants in the access token authorized to operate the scopes granted?", requestId)

  strGrantedScopes := strings.Join(grantedScopes, ",")
  environment.DebugLog(route.LogId, "authorizationRequired", "Valid scopes: " + strGrantedScopes, requestId)
  return grantedScopes, nil
}
