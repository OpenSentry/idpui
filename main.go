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
  //"github.com/charmixer/idpui/controllers/callbacks"

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

  clientId := config.GetString("oauth2.client.id")
  if clientId == "" {
    log.Panic("Missing config oauth2.client.id")
    return
  }

  clientSecret := config.GetString("oauth2.client.secret")
  if clientSecret == "" {
    log.Panic("Missing config oauth2.client.secret")
    return
  }

  // IdpApi needs to be able to act as an App using its client_id to bootstrap Authorization Code flow
  // Eg. Users accessing /me directly from browser.
  /*hydraConfig := &oauth2.Config{
    ClientID:     clientId,
    ClientSecret: clientSecret,
    Endpoint:     endpoint,
    RedirectURL:  config.GetString("oauth2.callback"),
    Scopes:       config.GetStringSlice("oauth2.scopes.required"),
  }*/

  // IdpFe needs to be able as an App using client_id to access idp endpoints. Using client credentials flow
  idpConfig := &clientcredentials.Config{
    ClientID:  clientId,
    ClientSecret: clientSecret,
    TokenURL: provider.Endpoint().TokenURL,
    Scopes: config.GetStringSlice("oauth2.scopes.required"),
    EndpointParams: url.Values{"audience": {"idp"}},
    AuthStyle: 2, // https://godoc.org/golang.org/x/oauth2#AuthStyle
  }

  aapConfig := &clientcredentials.Config{
    ClientID:  clientId,
    ClientSecret: clientSecret,
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

      SessionCredentialsStoreKey: appName + ".credentials",
      SessionStoreKey: appName,
      SessionExchangeStateKey: "exchange.state",
      SessionClaimStateKey: "claim.state",
      SessionLogoutStateKey: "logout.state",

      ContextAccessTokenKey: "access_token",
      ContextIdTokenKey: "id_token",
      ContextIdTokenHintKey: "id_token_hint",
      ContextIdentityKey: "id",
      IdpClientKey: "idpclient",
      ContextOAuth2ConfigKey: "oauth2_config",

      IdentityStoreKey: "idstore",
    },
    Provider: provider,
    // OAuth2Delegators: &oAuth2Delegators,
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

  clientId := config.GetString("oauth2.client.id")
  clientSecret := config.GetString("oauth2.client.secret")
  endpoint := env.Provider.Endpoint()
  endpoint.AuthStyle = 2 // Force basic secret, so token exchange does not auto to post which we did not allow.

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
  r.Use(sessions.SessionsMany([]string{env.Constants.SessionStoreKey}, store))
  //r.Use(sessions.Sessions(env.Constants.SessionStoreKey, store))

  // Use CSRF on all idpui forms.
  adapterCSRF := adapter.Wrap(csrf.Protect([]byte(config.GetString("csrf.authKey")), csrf.Secure(true)))
  // r.Use(adapterCSRF) // Do not use this as it will make csrf tokens for public files aswell which is just extra data going over the wire, no need for that.

  r.Static("/public", "public")
  r.LoadHTMLGlob("views/*")

  // Public endpoints
  ep := r.Group("/")
  ep.Use(adapterCSRF)
  {
    // Signup
    ep.GET(  "/claim", credentials.ShowClaimEmail(env) )
    ep.POST( "/claim", credentials.SubmitClaimEmail(env) )

    ep.GET(  "/register", credentials.ShowRegistration(env) )
    ep.POST( "/register", credentials.SubmitRegistration(env) )

    // Signin
    loginConfig := &oauth2.Config{
      ClientID: clientId,
      ClientSecret: clientSecret,
      Endpoint: endpoint,
      RedirectURL: config.GetString("oauth2.callback"),
      Scopes: config.GetStringSlice("oauth2.scopes.required"),
    }
    ep.GET(  "/login", credentials.ShowLogin(env, loginConfig) )
    ep.POST( "/login", credentials.SubmitLogin(env) )

    // Logout
    // logoutConfig := &oauth2.Config{
    //   ClientID: clientId,
    //   ClientSecret: clientSecret,
    //   Endpoint: endpoint,
    //   RedirectURL: config.GetString("idpui.public.url") + config.GetString("idpui.public.endpoints.logout"),
    //   Scopes: []string{"openid", "offline", "idp:read:humans"},
    // }
    ep.GET( "/logout", credentials.ShowLogout(env))
    ep.POST( "/logout", credentials.SubmitLogout(env) )

    // Clear cookies shortcut - FIXME: This should not be needed once logout works correctly.
    ep.GET( "/seeyoulater", credentials.ShowSeeYouLater(env))

    // Verify OTP code
    ep.GET(  "/verify", credentials.ShowVerify(env) )
    ep.POST( "/verify", credentials.SubmitVerify(env) )

    // Verify email using OTP code
    ep.GET( "/emailconfirm", credentials.ShowEmailConfirm(env) )
    ep.POST( "/emailconfirm", credentials.SubmitEmailConfirm(env) )

    // Verify delete using OTP code
    ep.GET( "/deleteconfirm", credentials.ShowDeleteConfirm(env) )
    ep.POST( "/deleteconfirm", credentials.SubmitDeleteConfirm(env) )

    // ep.GET("/untilnexttime", credentials.ShowUntilNextTime(env))

    // Recover
    ep.GET(  "/recover", credentials.ShowRecover(env) )
    ep.POST( "/recover", credentials.SubmitRecover(env) )
    ep.GET(  "/recoververification", credentials.ShowRecoverVerification(env) )
    ep.POST( "/recoververification", credentials.SubmitRecoverVerification(env) )

    // # Endpoints that require authentication

    // Change password
    passwordConfig := &oauth2.Config{
      ClientID: clientId,
      ClientSecret: clientSecret,
      Endpoint: endpoint,
      RedirectURL: config.GetString("idpui.public.url") + config.GetString("idpui.public.endpoints.password"),
      Scopes: []string{"openid", "offline", "idp:read:humans", "idp:update:humans:password"},
    }
    ep.GET( "/password", app.RequestAccessToken(env, passwordConfig), credentials.ShowPassword(env))
    ep.POST( "/password", credentials.SubmitPassword(env, passwordConfig) ) // Renders the obtained access token in hidden input field for posting. (maybe it should just render into bearer token header?)

    // Enable TOTP
    totpConfig := &oauth2.Config{
      ClientID: clientId,
      ClientSecret: clientSecret,
      Endpoint: endpoint,
      RedirectURL: config.GetString("idpui.public.url") + config.GetString("idpui.public.endpoints.totp"),
      Scopes: []string{"openid", "offline", "idp:read:humans", "idp:update:humans:totp"},
    }
    ep.GET( "/totp", app.RequestAccessToken(env, totpConfig), credentials.ShowTotp(env))
    ep.POST( "/totp", credentials.SubmitTotp(env, totpConfig) )

    // Delete Profile
    deleteProfileConfig := &oauth2.Config{
      ClientID: clientId,
      ClientSecret: clientSecret,
      Endpoint: endpoint,
      RedirectURL: config.GetString("idpui.public.url") + config.GetString("idpui.public.endpoints.delete"),
      Scopes: []string{"openid", "offline", "idp:read:humans", "idp:delete:humans"},
    }
    ep.GET( "/delete", app.RequestAccessToken(env, deleteProfileConfig), credentials.ShowProfileDelete(env))
    ep.POST( "/delete", credentials.SubmitProfileDelete(env, deleteProfileConfig) )

  }

  r.RunTLS(":" + config.GetString("serve.public.port"), config.GetString("serve.tls.cert.path"), config.GetString("serve.tls.key.path"))
}