package main

import (
  "errors"
  "strings"
  "net/url"
  "net/http"
  "encoding/gob"
  "os"
  "golang.org/x/net/context"
  "golang.org/x/oauth2"
  "golang.org/x/oauth2/clientcredentials"
  "github.com/sirupsen/logrus"
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
  "golang-idp-fe/gateway/idpapi"
  "github.com/pborman/getopt"
)

func init() {
  err := config.InitConfigurations()
  if err != nil {
    logrus.Fatal(err)
  }
  gob.Register(&oauth2.Token{}) // This is required to make session in idpui able to persist tokens.
  gob.Register(&oidc.IDToken{})
  gob.Register(&idpapi.Profile{})
  gob.Register(make(map[string][]string))
}

const app = "idpui"

func main() {

  appFields := logrus.Fields{
    "appname": app,
    "func": "main",
  }

  provider, err := oidc.NewProvider(context.Background(), config.GetString("hydra.public.url") + "/")
  if err != nil {
    logrus.WithFields(appFields).WithFields(logrus.Fields{"component": "Hydra Provider"}).Info("oidc.NewProvider" + err.Error())
    return
  }

  // IdpFe needs to be able to act as an App using its client_id to bootstrap Authorization Code flow
  // Eg. Users accessing /me directly from browser.
  hydraConfig := &oauth2.Config{
    ClientID:     config.GetString("oauth2.client.id"),
    ClientSecret: config.GetString("oauth2.client.secret"),
    Endpoint:     provider.Endpoint(),
    RedirectURL:  config.GetString("oauth2.callback"),
    Scopes:       config.GetStringSlice("oauth2.scopes.required"),
  }

  // IdpFe needs to be able as an App using client_id to access idpapi endpoints. Using client credentials flow
  idpapiConfig := &clientcredentials.Config{
    ClientID:  config.GetString("oauth2.client.id"),
    ClientSecret: config.GetString("oauth2.client.secret"),
    TokenURL: provider.Endpoint().TokenURL,
    Scopes: config.GetStringSlice("oauth2.scopes.required"),
    EndpointParams: url.Values{"audience": {"idpapi"}},
    AuthStyle: 2, // https://godoc.org/golang.org/x/oauth2#AuthStyle
  }

  aapapiConfig := &clientcredentials.Config{
    ClientID:  config.GetString("oauth2.client.id"),
    ClientSecret: config.GetString("oauth2.client.secret"),
    TokenURL: provider.Endpoint().TokenURL,
    Scopes: config.GetStringSlice("oauth2.scopes.required"),
    EndpointParams: url.Values{"audience": {"aapapi"}},
    AuthStyle: 2, // https://godoc.org/golang.org/x/oauth2#AuthStyle
  }

  // Setup app state variables. Can be used in handler functions by doing closures see exchangeAuthorizationCodeCallback
  env := &environment.State{
    AppName: app,
    Provider: provider,
    HydraConfig: hydraConfig,
    IdpApiConfig: idpapiConfig,
    AapApiConfig: aapapiConfig,
  }

  //optServe := getopt.BoolLong("serve", 0, "Serve application")
  optHelp := getopt.BoolLong("help", 0, "Help")
  getopt.Parse()

  if *optHelp {
    getopt.Usage()
    os.Exit(0)
  }

  //if *optServe {
    serve(env)
  /*} else {
    getopt.Usage()
    os.Exit(0)
  }*/

}

func serve(env *environment.State) {
  r := gin.Default()
  r.Use(ginrequestid.RequestId())
  r.Use(logger(env))

  store := cookie.NewStore([]byte(config.GetString("session.authKey")))
  // Ref: https://godoc.org/github.com/gin-gonic/contrib/sessions#Options
  store.Options(sessions.Options{
    MaxAge: 86400,
    Path: "/",
    Secure: true,
    HttpOnly: true,
  })
  r.Use(sessions.Sessions(environment.SessionStoreKey, store))

  // Use CSRF on all idpui forms.
  adapterCSRF := adapter.Wrap(csrf.Protect([]byte(config.GetString("csrf.authKey")), csrf.Secure(true)))
  // r.Use(adapterCSRF) // Do not use this as it will make csrf tokens for public files aswell which is just extra data going over the wire, no need for that.

  r.Static("/public", "public")
  r.LoadHTMLGlob("views/*")

  // Setup routes to use, this defines log for debug log
  routes := map[string]environment.Route{
    "/":               environment.Route{URL: "/", LogId: "idpui://"},
    "/authenticate":   environment.Route{URL: "/authenticate",LogId: "idpui://authenticate"},
    "/logout":         environment.Route{URL: "/logout",LogId: "idpui://logout"},
    "/session/logout": environment.Route{URL: "/session/logout",LogId: "idpui://session/logout"},
    "/register":       environment.Route{URL: "/register",LogId: "idpui://register"},
    "/recover":        environment.Route{URL: "/recover",LogId: "idpui://recover"},
    "/callback":       environment.Route{URL: "/callback",LogId: "idpui://callback"},
    "/me":             environment.Route{URL: "/me",LogId: "idpui://me"},
    "/password":       environment.Route{URL: "/password",LogId: "idpui//password"},
    "/consent":        environment.Route{URL: "/consent",LogId: "idpui://consent"},
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

    ep.GET(routes["/password"].URL, AuthenticationAndAuthorizationRequired(env, routes["/password"], "openid"), controllers.ShowPassword(env, routes["/password"]))
    ep.POST(routes["/password"].URL, AuthenticationAndAuthorizationRequired(env, routes["/password"], "openid"), controllers.SubmitPassword(env, routes["/password"]))

    ep.GET(routes["/consent"].URL, AuthenticationAndAuthorizationRequired(env, routes["/consent"], "openid"), controllers.ShowConsent(env, routes["/consent"]))
    ep.POST(routes["/consent"].URL, AuthenticationAndAuthorizationRequired(env, routes["/consent"], "openid"), controllers.SubmitConsent(env, routes["/consent"]))
  }

  r.RunTLS(":" + config.GetString("serve.public.port"), config.GetString("serve.tls.cert.path"), config.GetString("serve.tls.key.path"))
}

func logger(env *environment.State) gin.HandlerFunc {
  fn := func(c *gin.Context) {
    var requestId string = c.MustGet(environment.RequestIdKey).(string)
    logger := logrus.New() // Use this to direct request log somewhere else than app log
    //logger.SetFormatter(&logrus.JSONFormatter{})
    requestLog := logger.WithFields(logrus.Fields{
      "appname": env.AppName,
      "requestid": requestId,
    })
    c.Set(environment.LogKey, requestLog)
    c.Next()
  }
  return gin.HandlerFunc(fn)
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

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "route.logid": route.LogId,
      "component": "idpui.Authentication",
      "func": "main.AuthenticationAndAuthorizationRequired",
    })

    // Authentication
    token, err := authenticationRequired(env, c, route, log)
    if err != nil {
      // Require authentication to access resources. Init oauth2 Authorization code flow with idpui as the client.
      log.Debug("Error: " + err.Error())

      initUrl, err := controllers.StartAuthentication(env, c, route, log)
      if err != nil {
        log.Debug("Error: " + err.Error())
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
    grantedScopes, err := authorizationRequired(env, c, route, log, requiredScopes)
    if err != nil {
      log.Debug("Error: " + err.Error())
      c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
      c.Abort()
      return
    }
    log.Debug(grantedScopes)

    log.WithFields(logrus.Fields{"fixme":1}).Debug("Find IdToken for access token")
    idToken := &oauth2.Token{}
    c.Set(environment.IdTokenKey, idToken) // Authorized

    c.Next() // Authentication and authorization successful, continue.
    return
  }
  return gin.HandlerFunc(fn)
}

func authenticationRequired(env *environment.State, c *gin.Context, route environment.Route, log *logrus.Entry) (*oauth2.Token, error) {

  log = log.WithFields(logrus.Fields{
    "func": "main.AuthenticationAndAuthorizationRequired.authenticationRequired",
  })

  log.Debug("Checking Authorization: Bearer <token> in request")

  session := sessions.Default(c)

  var token *oauth2.Token
  auth := c.Request.Header.Get("Authorization")
  split := strings.SplitN(auth, " ", 2)
  if len(split) == 2 || strings.EqualFold(split[0], "bearer") {
    log.Debug("Authorization: Bearer <token> found for request")
    token = &oauth2.Token{
      AccessToken: split[1],
      TokenType: split[0],
    }
  } else {
    log.Debug("Checking Session <token> in request")
    v := session.Get(environment.SessionTokenKey)
    if v != nil {
      token = v.(*oauth2.Token)
      log.Debug("Session <token> found in request")
    }
  }

  tokenSource := env.HydraConfig.TokenSource(oauth2.NoContext, token)
  newToken, err := tokenSource.Token()
  if err != nil {
    return nil, err
  }

  if newToken.AccessToken != token.AccessToken {
    log.Debug("Token was refresed. Updated session token to match new token")
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
    log.Debug("Valid access token")

    // See #5 of QTNA
    log.WithFields(logrus.Fields{"fixme":1}).Debug("Missing implementation of QTNA #5 - Is the access token revoked?") // Call token revoked list to check if token is revoked.

    return token, nil
  }

  // Deny by default
  log.Debug("Missing or invalid access token")
  return nil, errors.New("Missing or invalid access token")
}

func authorizationRequired(env *environment.State, c *gin.Context, route environment.Route, log *logrus.Entry, requiredScopes []string) ([]string, error) {

  log = log.WithFields(logrus.Fields{
    "func": "main.AuthenticationAndAuthorizationRequired.authorizationRequired",
  })

  log.Debug("Checking required scopes for request")

  var grantedScopes []string

  // See #3 of QTNA
  log.Debug("Missing implementation of QTNA #3 - Is the access token granted the required scopes?")
  /*aapapiClient := aapapi.NewAapApiClient(env.AapApiConfig)
  grantedScopes, err := aapapi.IsRequiredScopesGrantedForToken(config.aapapi.AuthorizationsUrl, aapapiClient, requiredScopes)
  if err != nil {
    return nil, err
  }*/

  // See #4 of QTNA
  // FIXME: Is user who granted the scopes allow to use the scopes (check aapapi model for what user is allowed to do.)
  log.Debug("Missing implementation of QTNA #4 - Is the user or client giving the grants in the access token authorized to operate the scopes granted?")

  strGrantedScopes := strings.Join(grantedScopes, ",")
  log.Debug("Valid scopes: " + strGrantedScopes)
  return grantedScopes, nil
}
