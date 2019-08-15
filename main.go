package main

import (
  "errors"
  "strings"
  "net/url"
  "net/http"
  "encoding/gob"
  "os"
  "time"
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
  log = logrus.New();

  err := config.InitConfigurations()
  if err != nil {
    log.Panic(err.Error())
    return
  }

  logDebug = config.GetInt("log.debug")
  logFormat = config.GetString("log.format")

  // We only have 2 log levels. Things developers care about (debug) and things the user of the app cares about (info)
  log = logrus.New();
  if logDebug == 1 {
    log.SetLevel(logrus.DebugLevel)
  } else {
    log.SetLevel(logrus.InfoLevel)
  }
  if logFormat == "json" {
    log.SetFormatter(&logrus.JSONFormatter{})
  }

  appFields = logrus.Fields{
    "appname": app,
    "log.debug": logDebug,
    "log.format": logFormat,
  }

  gob.Register(&oauth2.Token{}) // This is required to make session in idpui able to persist tokens.
  gob.Register(&oidc.IDToken{})
  gob.Register(&idpapi.Profile{})
  gob.Register(make(map[string][]string))
}

const app = "idpui"

var (
  logDebug int // Set to 1 to enable debug
  logFormat string // Current only supports default and json

  log *logrus.Logger

  appFields logrus.Fields
)

func main() {

  provider, err := oidc.NewProvider(context.Background(), config.GetString("hydra.public.url") + "/")
  if err != nil {
    logrus.WithFields(appFields).Panic("oidc.NewProvider" + err.Error())
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
  r := gin.New() // Clean gin to take control with logging.
  r.Use(gin.Recovery())

  r.Use(ginrequestid.RequestId())
  r.Use(RequestLogger(env))

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
    "/":               environment.Route{URL: "/",               LogId: "idpui://"},
    "/authenticate":   environment.Route{URL: "/authenticate",   LogId: "idpui://authenticate"},
    "/logout":         environment.Route{URL: "/logout",         LogId: "idpui://logout"},
    "/session/logout": environment.Route{URL: "/session/logout", LogId: "idpui://session/logout"},
    "/register":       environment.Route{URL: "/register",       LogId: "idpui://register"},
    "/recover":        environment.Route{URL: "/recover",        LogId: "idpui://recover"},
    "/callback":       environment.Route{URL: "/callback",       LogId: "idpui://callback"},
    "/me":             environment.Route{URL: "/me",             LogId: "idpui://me"},
    "/me/edit":        environment.Route{URL: "/me/edit",        LogId: "idpui//me/edit"},
    "/password":       environment.Route{URL: "/password",       LogId: "idpui//password"},
    "/consent":        environment.Route{URL: "/consent",        LogId: "idpui://consent"},
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
    ep.GET(routes["/me/edit"].URL, AuthenticationAndAuthorizationRequired(env, routes["/me/edit"], "openid"), controllers.ShowProfileEdit(env, routes["/me/edit"]))
    ep.POST(routes["/me/edit"].URL, AuthenticationAndAuthorizationRequired(env, routes["/me/edit"], "openid"), controllers.SubmitProfileEdit(env, routes["/me/edit"]))

    ep.GET(routes["/password"].URL, AuthenticationAndAuthorizationRequired(env, routes["/password"], "openid"), controllers.ShowPassword(env, routes["/password"]))
    ep.POST(routes["/password"].URL, AuthenticationAndAuthorizationRequired(env, routes["/password"], "openid"), controllers.SubmitPassword(env, routes["/password"]))

    ep.GET(routes["/consent"].URL, AuthenticationAndAuthorizationRequired(env, routes["/consent"], "openid"), controllers.ShowConsent(env, routes["/consent"]))
    ep.POST(routes["/consent"].URL, AuthenticationAndAuthorizationRequired(env, routes["/consent"], "openid"), controllers.SubmitConsent(env, routes["/consent"]))
  }

  r.RunTLS(":" + config.GetString("serve.public.port"), config.GetString("serve.tls.cert.path"), config.GetString("serve.tls.key.path"))
}

func RequestLogger(env *environment.State) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    // Start timer
    start := time.Now()
    path := c.Request.URL.Path
    raw := c.Request.URL.RawQuery

    var requestId string = c.MustGet(environment.RequestIdKey).(string)
    requestLog := log.WithFields(appFields).WithFields(logrus.Fields{
      "request.id": requestId,
    })
    c.Set(environment.LogKey, requestLog)

		c.Next()

		// Stop timer
		stop := time.Now()
		latency := stop.Sub(start)

    ipData, err := getRequestIpData(c.Request)
    if err != nil {
      log.WithFields(appFields).WithFields(logrus.Fields{
        "func": "RequestLogger",
      }).Debug(err.Error())
    }

    forwardedForIpData, err := getForwardedForIpData(c.Request)
    if err != nil {
      log.WithFields(appFields).WithFields(logrus.Fields{
        "func": "RequestLogger",
      }).Debug(err.Error())
    }

		method := c.Request.Method
		statusCode := c.Writer.Status()
		errorMessage := c.Errors.ByType(gin.ErrorTypePrivate).String()

		bodySize := c.Writer.Size()

    var fullpath string = path
		if raw != "" {
			fullpath = path + "?" + raw
		}

		log.WithFields(appFields).WithFields(logrus.Fields{
      "latency": latency,
      "forwarded_for.ip": forwardedForIpData.Ip,
      "forwarded_for.port": forwardedForIpData.Port,
      "ip": ipData.Ip,
      "port": ipData.Port,
      "method": method,
      "status": statusCode,
      "error": errorMessage,
      "body_size": bodySize,
      "path": fullpath,
      "request.id": requestId,
    }).Info("")
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
      "func": "AuthenticationAndAuthorizationRequired",
    })

    // Authentication
    token, err := authenticationRequired(env, c, route, log)
    if err != nil {
      // Require authentication to access resources. Init oauth2 Authorization code flow with idpui as the client.
      log.Debug(err.Error())

      initUrl, err := controllers.StartAuthentication(env, c, route, log)
      if err != nil {
        log.Debug(err.Error())
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
    _ /* grantedScopes */, err = authorizationRequired(env, c, route, log, requiredScopes)
    if err != nil {
      log.Debug(err.Error())
      c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    log.WithFields(logrus.Fields{"fixme":1}).Debug("Missing id_token. Write code to find it correctly")
    idToken := &oauth2.Token{}
    c.Set(environment.IdTokenKey, idToken) // Authorized

    c.Next() // Authentication and authorization successful, continue.
    return
  }
  return gin.HandlerFunc(fn)
}

func authenticationRequired(env *environment.State, c *gin.Context, route environment.Route, log *logrus.Entry) (*oauth2.Token, error) {
  session := sessions.Default(c)

  log = log.WithFields(logrus.Fields{
    "func": "authenticationRequired",
  })

  logWithBearer := log.WithFields(logrus.Fields{"authorization": "bearer"})
  logWithSession := log.WithFields(logrus.Fields{"authorization": "session"})

  logWithBearer.Debug("Looking for access token")
  var token *oauth2.Token
  auth := c.Request.Header.Get("Authorization")
  split := strings.SplitN(auth, " ", 2)
  if len(split) == 2 || strings.EqualFold(split[0], "bearer") {
    logWithBearer.Debug("Found access token")
    token = &oauth2.Token{
      AccessToken: split[1],
      TokenType: split[0],
    }
    log = logWithBearer
  } else {
    logWithSession.Debug("Looking for access token")
    v := session.Get(environment.SessionTokenKey)
    if v != nil {
      token = v.(*oauth2.Token)
      logWithSession.Debug("Found access token")
    }
    log = logWithSession
  }

  tokenSource := env.HydraConfig.TokenSource(oauth2.NoContext, token)
  newToken, err := tokenSource.Token()
  if err != nil {
    return nil, err
  }

  if newToken.AccessToken != token.AccessToken {
    log.Debug("Refreshed access token. Session updated")
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
    log.WithFields(logrus.Fields{"fixme": 1, "qtna": 5}).Debug("Missing check against token-revoked-list to check if token is revoked") // Call token revoked list to check if token is revoked.

    return token, nil
  }

  // Deny by default
  return nil, errors.New("Invalid access token")
}

func authorizationRequired(env *environment.State, c *gin.Context, route environment.Route, log *logrus.Entry, requiredScopes []string) ([]string, error) {

  log = log.WithFields(logrus.Fields{
    "func": "authorizationRequired",
  })

  strRequiredScopes := strings.Join(requiredScopes, ",")
  log.WithFields(logrus.Fields{"scopes": strRequiredScopes}).Debug("Looking for required scopes");

  var grantedScopes []string

  // See #3 of QTNA
  log.WithFields(logrus.Fields{"fixme": 1, "qtna": 3}).Debug("Missing check if access token is granted the required scopes")

  /*aapapiClient := aapapi.NewAapApiClient(env.AapApiConfig)
  grantedScopes, err := aapapi.IsRequiredScopesGrantedForToken(config.aapapi.AuthorizationsUrl, aapapiClient, requiredScopes)
  if err != nil {
    return nil, err
  }*/

  // See #4 of QTNA
  log.WithFields(logrus.Fields{"fixme": 1, "qtna": 4}).Debug("Missing check if the user or client giving the grants in the access token  isauthorized to operate the granted scopes")

  strGrantedScopes := strings.Join(grantedScopes, ",")
  log.WithFields(logrus.Fields{"scopes": strGrantedScopes}).Debug("Found required scopes");
  return grantedScopes, nil
}
