package main

import (
  "net/url"
  "encoding/gob"
  "os"
  "runtime"
  "path"
  "fmt"
  "golang.org/x/net/context"
  "golang.org/x/oauth2/clientcredentials"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gin-contrib/sessions"
  "github.com/gin-contrib/sessions/cookie"
  "github.com/gorilla/csrf"
  "github.com/gwatts/gin-adapter"
  oidc "github.com/coreos/go-oidc"
  "github.com/pborman/getopt"

  "github.com/opensentry/idpui/app"
  "github.com/opensentry/idpui/config"
  "github.com/opensentry/idpui/controllers/challenges"
  "github.com/opensentry/idpui/controllers/credentials"
  "github.com/opensentry/idpui/controllers/profiles"
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

  log.SetReportCaller(true)
  log.Formatter = &logrus.TextFormatter{
    CallerPrettyfier: func(f *runtime.Frame) (string, string) {
      filename := path.Base(f.File)
      return "", fmt.Sprintf("%s:%d", filename, f.Line)
    },
  }

  // We only have 2 log levels. Things developers care about (debug) and things the user of the app cares about (info)
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

  // IdpUI needs to be able as an App using client_id to access idp endpoints. Using client credentials flow
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

      SessionStoreKey: appName,
      SessionRedirectCsrfStoreKey: appName + ".redirectcsrf",
      SessionChallengeStoreKey: appName + ".challenges",
      SessionLogoutStateKey: "logout.state",

      ContextAccessTokenKey: "access_token",
      ContextIdTokenKey: "id_token",
      ContextIdTokenHintKey: "id_token_hint",
      ContextIdentityKey: "id",
      ContextOAuth2ConfigKey: "oauth2_config",
      ContextRequiredScopesKey: "required_scopes",
      ContextPrecalculatedStateKey: "precalculated_state",
    },
    Provider: provider,
    ClientId: clientId,
    ClientSecret: clientSecret,
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
  r.Use(sessions.SessionsMany([]string{env.Constants.SessionRedirectCsrfStoreKey, env.Constants.SessionStoreKey, env.Constants.SessionChallengeStoreKey}, store))

  // Use CSRF on all idpui forms.
  adapterCSRF := adapter.Wrap(csrf.Protect([]byte(config.GetString("csrf.authKey")), csrf.Secure(true)))
  // r.Use(adapterCSRF) // Do not use this as it will make csrf tokens for public files aswell which is just extra data going over the wire, no need for that.

  r.Static("/public", "public")
  r.LoadHTMLGlob("views/*")

  // Public endpoints
  ep := r.Group("/")
  ep.Use(adapterCSRF)
  {
    // Public profile
    ep.GET("/profile", profiles.ShowPublicProfile(env) )

    // Signup
    ep.GET(  "/claim", credentials.ShowClaimEmail(env) )
    ep.POST( "/claim", credentials.SubmitClaimEmail(env) )

    ep.GET(  "/register", credentials.ShowRegistration(env) )
    ep.POST( "/register", credentials.SubmitRegistration(env) )

    // Signin
    ep.GET(  "/login", credentials.ShowLogin(env) )
    ep.POST( "/login", credentials.SubmitLogin(env) )

    // Verify OTP code
    ep.GET(  "/verify", challenges.ShowVerify(env) )
    ep.POST( "/verify", challenges.SubmitVerify(env) )

    // Verify email using OTP code
    ep.GET( "/emailconfirm", challenges.ShowEmailConfirm(env) )
    ep.POST( "/emailconfirm", challenges.SubmitEmailConfirm(env) )

    // Logout
    ep.GET( "/logout", credentials.ShowLogout(env))
    ep.POST( "/logout", credentials.SubmitLogout(env) )

    // Clear cookies shortcut - FIXME: This should not be needed once logout works correctly.
    ep.GET( "/seeyoulater", credentials.ShowSeeYouLater(env))

    // Verify delete using OTP code
    ep.GET( "/deleteconfirm", challenges.ShowDeleteConfirm(env) )
    ep.POST( "/deleteconfirm", challenges.SubmitDeleteConfirm(env) )

    // Recover
    ep.GET(  "/recover", credentials.ShowRecover(env) )
    ep.POST( "/recover", credentials.SubmitRecover(env) )

    // Verify recover using OTP code
    ep.GET( "/recoverconfirm", challenges.ShowRecoverConfirm(env) )
    ep.POST( "/recoverconfirm", challenges.SubmitRecoverConfirm(env) )

    // # Endpoints that require authentication
    ep := r.Group("/")
    ep.Use(adapterCSRF)
    ep.Use(app.RequireScopes(env, "openid", "idp:read:humans"))
    {
      // Password change
      ep.GET(  "/password",
        app.RequireScopes(env, "idp:update:humans:password"),
        app.ConfigureOauth2(env),
        app.RequestTokenUsingAuthorizationCode(env),
        app.RequireIdentity(env),
        credentials.ShowPassword(env),
      )
      ep.POST( "/password", // Renders the access token obtained in the GET request in a hidden input field for posting. (maybe it should just render into bearer token header?)
        app.RequireScopes(env, "idp:update:humans:password"),
        app.ConfigureOauth2(env),
        credentials.SubmitPassword(env),
      )

      // TOTP setup
      ep.GET(  "/totp",
        app.RequireScopes(env, "idp:update:humans:totp"),
        app.ConfigureOauth2(env),
        app.RequestTokenUsingAuthorizationCode(env),
        app.RequireIdentity(env),
        credentials.ShowTotp(env),
      )
      ep.POST( "/totp",
        app.RequireScopes(env, "idp:update:humans:totp"),
        app.ConfigureOauth2(env),
        credentials.SubmitTotp(env),
      )

      // Delete identity
      ep.GET(  "/delete",
        app.RequireScopes(env, "idp:delete:humans"),
        app.ConfigureOauth2(env),
        app.RequestTokenUsingAuthorizationCode(env),
        app.RequireIdentity(env),
        credentials.ShowProfileDelete(env),
      )
      ep.POST( "/delete",
        app.RequireScopes(env, "idp:delete:humans"),
        app.ConfigureOauth2(env),
        credentials.SubmitProfileDelete(env),
      )

      // Change email (change recovery email)
      ep.GET(  "/emailchange",
        app.RequireScopes(env, "idp:create:humans:emailchange"),
        app.ConfigureOauth2(env),
        app.RequestTokenUsingAuthorizationCode(env),
        app.RequireIdentity(env),
        credentials.ShowEmailChange(env),
      )
      ep.POST( "/emailchange",
        app.RequireScopes(env, "idp:create:humans:emailchange"),
        app.ConfigureOauth2(env),
        credentials.SubmitEmailChange(env),
      )

/*

Challenge {
  Id: UUID,
  Sub: UUID (human)
  RedirectToOnSuccess: URL
  Data: Custom Defined
}

Change email kræver identification for at få et access token til at lave challenge til at begynde med. I challenge gemmes email som der skal skiftes til.

Redirect til challenge verifier for challenge.Id

On success redirect Challenge.RedirectTo?challenge_id

Controller som modtager verified challenge skal.
1. Authenticate brugere for at få et access token til at gøre noget. !!!! THIS HERE CANT BE DONE WITH HYDRA redirect_uris have no params... Need to store the session of what challenge is beeing access somewhere else?
2. Tjekke at sub challenge og sub i token er den samme
3. Kalde PUT /email (token, id, challenge.data.email)

WARNING: Using data on the challenge will effectivly split the transaction into a verify code part and and execute data change part. This will be prone to network errors, meaning a code might be validated, but client failed to get redirection of execution controller. WHAT TO DO?

*/

      // Confirmation of the challenge required to change email
      ep.GET(  "/emailchangeconfirm",
        app.RequireScopes(env, "idp:update:humans:emailchange"),
        app.UsePrecalculatedStateFromQuery(env, "email_challenge"),
        app.ConfigureOauth2(env),
        app.RequestTokenUsingAuthorizationCode(env),
        app.RequireIdentity(env),
        challenges.ShowEmailChangeConfirm(env),
      )
      ep.POST( "/emailchangeconfirm",
        app.RequireScopes(env, "idp:update:humans:emailchange"),
        app.ConfigureOauth2(env),
        challenges.SubmitEmailChangeConfirm(env),
      )

      // TODO: Delete confirm should be here to.
    }

  }

  r.RunTLS(":" + config.GetString("serve.public.port"), config.GetString("serve.tls.cert.path"), config.GetString("serve.tls.key.path"))
}
