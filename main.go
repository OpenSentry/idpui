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
  "github.com/gofrs/uuid"
  oidc "github.com/coreos/go-oidc"
  "github.com/pborman/getopt"

  "github.com/charmixer/idpui/config"
  "github.com/charmixer/idpui/environment"
  "github.com/charmixer/idpui/utils"
  "github.com/charmixer/idpui/controllers/credentials"
  "github.com/charmixer/idpui/controllers/callbacks"
  "github.com/charmixer/idpui/controllers/profiles"
)

const app = "idpui"

var (
  logDebug int // Set to 1 to enable debug
  logFormat string // Current only supports default and json

  log *logrus.Logger

  appFields logrus.Fields
  sessionKeys environment.SessionKeys
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

  sessionKeys = environment.SessionKeys{
    SessionAppStore: app,
  }

  gob.Register(&oauth2.Token{}) // This is required to make session in idpui able to persist tokens.
  gob.Register(&oidc.IDToken{})
  //gob.Register(&idp.Profile{})
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
  env := &environment.State{
    SessionKeys: &sessionKeys,
    Provider: provider,
    HydraConfig: hydraConfig,
    IdpApiConfig: idpConfig,
    AapApiConfig: aapConfig,
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

  r.Use(requestId())
  r.Use(RequestLogger(env))

  store := cookie.NewStore([]byte(config.GetString("session.authKey")))
  // Ref: https://godoc.org/github.com/gin-gonic/contrib/sessions#Options
  store.Options(sessions.Options{
    MaxAge: 86400,
    Path: "/",
    Secure: true,
    HttpOnly: true,
  })
  r.Use(sessions.Sessions(env.SessionKeys.SessionAppStore, store))

  // Use CSRF on all idpui forms.
  adapterCSRF := adapter.Wrap(csrf.Protect([]byte(config.GetString("csrf.authKey")), csrf.Secure(true)))
  // r.Use(adapterCSRF) // Do not use this as it will make csrf tokens for public files aswell which is just extra data going over the wire, no need for that.

  r.Static("/public", "public")
  r.LoadHTMLGlob("views/*")

  ep := r.Group("/")
  ep.Use(adapterCSRF)
  {
    // Token exchange
    // FIXME: Must be public accessible until we figure out to enfore that only hydra client may make callbacks
    ep.GET("/callback", callbacks.ExchangeAuthorizationCodeCallback(env) )

    // Signin
    ep.GET(  "/login", credentials.ShowLogin(env) )
    ep.POST( "/login", credentials.SubmitLogin(env) )

    // Verify OTP code
    ep.GET(  "/verify", credentials.ShowVerify(env) )
    ep.POST( "/verify", credentials.SubmitVerify(env) )

    // Enable TOTP
    ep.GET(  "/totp", AuthenticationAndAuthorizationRequired(env, "openid"), credentials.ShowTotp(env) )
    ep.POST( "/totp", AuthenticationAndAuthorizationRequired(env, "openid"), credentials.SubmitTotp(env) )

    // Change password
    ep.GET(  "/password", AuthenticationAndAuthorizationRequired(env, "openid"), credentials.ShowPassword(env) )
    ep.POST( "/password", AuthenticationAndAuthorizationRequired(env, "openid"), credentials.SubmitPassword(env) )

    // Signup
    ep.GET(  "/register", credentials.ShowRegistration(env) )
    ep.POST( "/register", credentials.SubmitRegistration(env) )

    // Profile
    ep.GET(  "/",        AuthenticationAndAuthorizationRequired(env, "openid"), profiles.ShowProfile(env) )
    ep.GET(  "/me",      AuthenticationAndAuthorizationRequired(env, "openid"), profiles.ShowProfile(env) )
    ep.GET(  "/me/edit", AuthenticationAndAuthorizationRequired(env, "openid"), profiles.ShowProfileEdit(env) )
    ep.POST( "/me/edit", AuthenticationAndAuthorizationRequired(env, "openid"), profiles.SubmitProfileEdit(env) )

    ep.GET(  "/profile", profiles.ShowPublicProfile(env) )

    // Signoff
    ep.GET(  "/logout", AuthenticationAndAuthorizationRequired(env, "openid"), profiles.ShowLogout(env) )
    ep.POST( "/logout", AuthenticationAndAuthorizationRequired(env, "openid"), profiles.SubmitLogout(env) )

    // These does not require authentication as its like doing delete in browser on cookies.
    // FIXME: Read up on Front Channel logout and Backchannel logout in Hydra an use that.
    ep.GET(  "/session/logout", profiles.ShowLogoutSession(env) )
    ep.POST( "/session/logout", profiles.SubmitLogoutSession(env) )


    ep.GET(  "/recover", profiles.ShowRecover(env) )
    ep.POST( "/recover", profiles.SubmitRecover(env) )
    ep.GET(  "/recoververification", credentials.ShowRecoverVerification(env) )
    ep.POST( "/recoververification", credentials.SubmitRecoverVerification(env) )

    ep.GET(  "/invite", AuthenticationAndAuthorizationRequired(env, "openid"), profiles.ShowInvite(env) )
    ep.POST( "/invite", AuthenticationAndAuthorizationRequired(env, "openid"), profiles.SubmitInvite(env) )

    ep.GET(  "/me/delete",             AuthenticationAndAuthorizationRequired(env, "openid"), profiles.ShowProfileDelete(env) )
    ep.POST( "/me/delete",             AuthenticationAndAuthorizationRequired(env, "openid"), profiles.SubmitProfileDelete(env) )
    ep.GET(  "/me/deleteverification", AuthenticationAndAuthorizationRequired(env, "openid"), credentials.ShowProfileDeleteVerification(env) )
    ep.POST( "/me/deleteverification", AuthenticationAndAuthorizationRequired(env, "openid"), credentials.SubmitProfileDeleteVerification(env) )

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

    ipData, err := utils.GetRequestIpData(c.Request)
    if err != nil {
      log.WithFields(appFields).WithFields(logrus.Fields{
        "func": "RequestLogger",
      }).Debug(err.Error())
    }

    forwardedForIpData, err := utils.GetForwardedForIpData(c.Request)
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

    // if public data is requested successfully, then dont log it since its just spam when debugging
    if strings.Contains(path, "/public/") && ( statusCode == http.StatusOK || statusCode == http.StatusNotModified ) {
     return
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
func AuthenticationAndAuthorizationRequired(env *environment.State, requiredScopes ...string) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "AuthenticationAndAuthorizationRequired",
    })

    // Authentication
    token, err := authenticationRequired(env, c, log)
    if err != nil {
      // Require authentication to access resources. Init oauth2 Authorization code flow with idpui as the client.
      log.Debug(err.Error())

      initUrl, err := credentials.StartAuthenticationSession(env, c, log)
      if err != nil {
        log.Debug(err.Error())
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }
      c.Redirect(http.StatusFound, initUrl.String())
      c.Abort()
      return
    }
    c.Set(environment.AccessTokenKey, token) // Authenticated, so use it forward.

    // Authorization
    _ /* grantedScopes */, err = authorizationRequired(env, c, log, requiredScopes)
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

func authenticationRequired(env *environment.State, c *gin.Context, log *logrus.Entry) (*oauth2.Token, error) {
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
      logWithSession.Debug("Found access token")
      token = v.(*oauth2.Token)
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

func authorizationRequired(env *environment.State, c *gin.Context, log *logrus.Entry, requiredScopes []string) ([]string, error) {

  log = log.WithFields(logrus.Fields{
    "func": "authorizationRequired",
  })

  strRequiredScopes := strings.Join(requiredScopes, ",")
  log.WithFields(logrus.Fields{"scopes": strRequiredScopes}).Debug("Looking for required scopes");

  var grantedScopes []string

  // See #3 of QTNA
  log.WithFields(logrus.Fields{"fixme": 1, "qtna": 3}).Debug("Missing check if access token is granted the required scopes")

  /*aapClient := aap.NewAapApiClient(env.AapApiConfig)
  grantedScopes, err := aap.IsRequiredScopesGrantedForToken(config.aap.AuthorizationsUrl, aapClient, requiredScopes)
  if err != nil {
    return nil, err
  }*/

  // See #4 of QTNA
  log.WithFields(logrus.Fields{"fixme": 1, "qtna": 4}).Debug("Missing check if the user or client giving the grants in the access token  isauthorized to operate the granted scopes")

  strGrantedScopes := strings.Join(grantedScopes, ",")
  log.WithFields(logrus.Fields{"scopes": strGrantedScopes}).Debug("Found required scopes");
  return grantedScopes, nil
}

func requestId() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check for incoming header, use it if exists
		requestID := c.Request.Header.Get("X-Request-Id")

		// Create request id with UUID4
		if requestID == "" {
			uuid4, _ := uuid.NewV4()
			requestID = uuid4.String()
		}

		// Expose it for use in the application
		c.Set("RequestId", requestID)

		// Set X-Request-Id header
		c.Writer.Header().Set("X-Request-Id", requestID)
		c.Next()
	}
}
