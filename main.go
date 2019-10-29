package main

import (
  "net/url"
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
  oidc "github.com/coreos/go-oidc"
  "github.com/pborman/getopt"

  "github.com/charmixer/idpui/app"
  "github.com/charmixer/idpui/config"
  "github.com/charmixer/idpui/controllers/credentials"
  "github.com/charmixer/idpui/controllers/callbacks"

)

const appName = "idpui"

var (
  logDebug int // Set to 1 to enable debug
  logFormat string // Current only supports default and json

  log *logrus.Logger

  appFields logrus.Fields
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
    "appname": appName,
    "log.debug": logDebug,
    "log.format": logFormat,
  }

  gob.Register(&app.IdentityStore{})

  //gob.Register(&oauth2.Token{}) // This is required to make session in idpui able to persist tokens.
  //gob.Register(&oidc.IDToken{})
  gob.Register(make(map[string][]string))
}

func main() {

  provider, err := oidc.NewProvider(context.Background(), config.GetString("hydra.public.url") + "/")
  if err != nil {
    logrus.WithFields(appFields).Panic("oidc.NewProvider" + err.Error())
    return
  }

  endpoint := provider.Endpoint()
  endpoint.AuthStyle = 2 // Force basic secret, so token exchange does not auto to post which we did not allow.


  // IdpApi needs to be able to act as an App using its client_id to bootstrap Authorization Code flow
  // Eg. Users accessing /me directly from browser.
  hydraConfig := &oauth2.Config{
    ClientID:     config.GetString("oauth2.client.id"),
    ClientSecret: config.GetString("oauth2.client.secret"),
    Endpoint:     endpoint,
    RedirectURL:  config.GetString("oauth2.callback"),
    Scopes:       config.GetStringSlice("oauth2.scopes.required"),
  }

  // IdpFe needs to be able as an App using client_id to access idp endpoints. Using client credentials flow
  idpConfig := &clientcredentials.Config{
    ClientID:  config.GetString("oauth2.client.id"),
    ClientSecret: config.GetString("oauth2.client.secret"),
    TokenURL: provider.Endpoint().TokenURL,
    Scopes: config.GetStringSlice("oauth2.scopes.required"),
    EndpointParams: url.Values{"audience": {"idp"}},
    AuthStyle: 2, // https://godoc.org/golang.org/x/oauth2#AuthStyle
  }

  aapConfig := &clientcredentials.Config{
    ClientID:  config.GetString("oauth2.client.id"),
    ClientSecret: config.GetString("oauth2.client.secret"),
    TokenURL: provider.Endpoint().TokenURL,
    Scopes: config.GetStringSlice("oauth2.scopes.required"),
    EndpointParams: url.Values{"audience": {"aap"}},
    AuthStyle: 2, // https://godoc.org/golang.org/x/oauth2#AuthStyle
  }

  // Setup app state variables. Can be used in handler functions by doing closures see exchangeAuthorizationCodeCallback
  env := &app.Environment{
    Constants: &app.EnvironmentConstants{
      RequestIdKey: "RequestId",
      LogKey: "log",
      AccessTokenKey: "access_token",
      IdTokenKey: "id_token",

      SessionStoreKey: appName,
      SessionExchangeStateKey: "exchange.state",
      SessionClaimStateKey: "claim.state",
      SessionLogoutStateKey: "logout.state",

      ContextAccessTokenKey: "access_token",
      ContextIdTokenKey: "id_token",
      ContextIdTokenHintKey: "id_token_hint",
      ContextIdentityKey: "id",

      IdentityStoreKey: "idstore",
    },
    Provider: provider,
    OAuth2Delegator: hydraConfig,
    IdpConfig: idpConfig,
    AapConfig: aapConfig,
    Logger: log,
  }

  optServe := getopt.BoolLong("serve", 0, "Serve application")
  optHelp := getopt.BoolLong("help", 0, "Help")
  getopt.Parse()

  if *optHelp {
    getopt.Usage()
    os.Exit(0)
  }

  if *optServe {
    serve(env)
  } else {
    getopt.Usage()
    os.Exit(0)
  }

}

func serve(env *app.Environment) {
  r := gin.New() // Clean gin to take control with logging.
  r.Use(gin.Recovery())

  r.Use(app.RequestId())
  r.Use(app.RequestLogger(env, appFields))

  store := cookie.NewStore([]byte(config.GetString("session.authKey")))
  // Ref: https://godoc.org/github.com/gin-gonic/contrib/sessions#Options
  store.Options(sessions.Options{
    MaxAge: 86400,
    Path: "/",
    Secure: true,
    HttpOnly: true,
  })
  r.Use(sessions.Sessions(env.Constants.SessionStoreKey, store))

  // Use CSRF on all idpui forms.
  adapterCSRF := adapter.Wrap(csrf.Protect([]byte(config.GetString("csrf.authKey")), csrf.Secure(true)))
  // r.Use(adapterCSRF) // Do not use this as it will make csrf tokens for public files aswell which is just extra data going over the wire, no need for that.

  r.Static("/public", "public")
  r.LoadHTMLGlob("views/*")

  // Public endpoints
  ep := r.Group("/")
  ep.Use(adapterCSRF)
  {
    // Token exchange
    // FIXME: Must be public accessible until we figure out to enfore that only hydra client may make callbacks
    ep.GET("/callback", callbacks.ExchangeAuthorizationCodeCallback(env) )

    // Signup
    ep.GET(  "/claim", credentials.ShowClaimEmail(env) )
    ep.POST( "/claim", credentials.SubmitClaimEmail(env) )

    ep.GET(  "/register", credentials.ShowRegistration(env) )
    ep.POST( "/register", credentials.SubmitRegistration(env) )

    // Signin
    ep.GET(  "/login", credentials.ShowLogin(env) )
    ep.POST( "/login", credentials.SubmitLogin(env) )

    // Signout
    ep.GET( "/seeyoulater", credentials.ShowSeeYouLater(env))

    // Verify OTP code
    ep.GET(  "/verify", credentials.ShowVerify(env) )
    ep.POST( "/verify", credentials.SubmitVerify(env) )

    // Verify email using OTP code
    ep.GET( "/emailconfirm", credentials.ShowEmailConfirm(env) )
    ep.POST( "/emailconfirm", credentials.SubmitEmailConfirm(env) )

    // Recover
    ep.GET(  "/recover", credentials.ShowRecover(env) )
    ep.POST( "/recover", credentials.SubmitRecover(env) )
    ep.GET(  "/recoververification", credentials.ShowRecoverVerification(env) )
    ep.POST( "/recoververification", credentials.SubmitRecoverVerification(env) )
  }

  // Endpoints that require Authentication and Authorization
  ep = r.Group("/")
  ep.Use(adapterCSRF)
  ep.Use( app.AuthenticationRequired(env) )
  ep.Use( app.RequireIdentity(env) ) // Checks Authorization
  {
    // Change password
    ep.GET(  "/password", credentials.ShowPassword(env) )
    ep.POST( "/password", credentials.SubmitPassword(env) )

    // Enable TOTP
    ep.GET(  "/totp", credentials.ShowTotp(env) )
    ep.POST( "/totp", credentials.SubmitTotp(env) )

    // Profile
    ep.GET(  "/delete",             credentials.ShowProfileDelete(env) )
    ep.POST( "/delete",             credentials.SubmitProfileDelete(env) )
    ep.GET(  "/deleteverification", credentials.ShowProfileDeleteVerification(env) )
    ep.POST( "/deleteverification", credentials.SubmitProfileDeleteVerification(env) )

    // Signout
    ep.GET(  "/logout", credentials.ShowLogout(env) )
    ep.POST( "/logout", credentials.SubmitLogout(env) )
  }

  r.RunTLS(":" + config.GetString("serve.public.port"), config.GetString("serve.tls.cert.path"), config.GetString("serve.tls.key.path"))
}