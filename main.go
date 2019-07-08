package main

import (
  "strings"
  "fmt"
  "net/url"
  "net/http"
  "encoding/base64"
  "encoding/gob"
  "crypto/rand"
  "reflect"

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
  "golang-idp-fe/gateway/idpbe"
)

type authenticationForm struct {
    Challenge string `form:"challenge"`
    Identity string `form:"identity"`
    Password string `form:"password"`
}

type registrationForm struct {
    Identity string `form:"identity"`
    Email string `form:"email"`
    Password string `form:"password"`
    PasswordRetyped string `form:"password_retyped"`
}

type recoverForm struct {
    Identity string `form:"identity"`
    Password string `form:"password"`
}

const sessionStoreKey = "idpfe"
const sessionTokenKey = "token"
const sessionIdTokenKey = "idtoken"
const sessionStateKey = "state"

func init() {
  config.InitConfigurations()

  gob.Register(&oauth2.Token{}) // This is required to make session in idp-fe able to persist tokens.
  gob.Register(&oidc.IDToken{})

}

const logIdpFeApp = "idp-fe"
func debugLog(app string, event string, msg string, requestId string) {
  if requestId == "" {
    fmt.Println(fmt.Sprintf("[app:%s][event:%s] %s", app, event, msg))
    return;
  }
  fmt.Println(fmt.Sprintf("[app:%s][request-id:%s][event:%s] %s", app, requestId, event, msg))
}

var (
  hydraConfig *oauth2.Config
  idpbeClient *idpbe.IdpBeClient
)


type HydraClient struct {
  *http.Client
}

type IdpFeEnv struct {
  Provider *oidc.Provider
  IdpBeClient *idpbe.IdpBeClient
  HydraConfig *oauth2.Config
}

func NewHydraClient(config *oauth2.Config, token *oauth2.Token) *HydraClient {
  ctx := context.Background()
  client := config.Client(ctx, token)
  return &HydraClient{client}
}

func main() {

  provider, err := oidc.NewProvider(context.Background(), config.Hydra.Url + "/")
  if err != nil {
    fmt.Println(err)
    return
  }
  fmt.Println(reflect.TypeOf(provider))

  // Setup hydra config. Used for Authorization code flow. (should this go into idpbe?)
  hydraConfig = &oauth2.Config{
    ClientID:     config.IdpFe.ClientId,
    ClientSecret: config.IdpFe.ClientSecret,
    Endpoint:     provider.Endpoint(),
    RedirectURL:  config.IdpFe.PublicCallbackUrl,
    Scopes:       config.IdpFe.RequiredScopes,
  }

  // Initialize the idp-be http client with client credentials token for use in the API.
  idpbeClient = idpbe.NewIdpBeClient(&clientcredentials.Config{
    ClientID:  config.IdpFe.ClientId,
    ClientSecret: config.IdpFe.ClientSecret,
    TokenURL: provider.Endpoint().TokenURL,
    Scopes: []string{"openid", "idpbe.authenticate"},
    EndpointParams: url.Values{"audience": {"idpbe"}},
    AuthStyle: 2, // https://godoc.org/golang.org/x/oauth2#AuthStyle
  })

  // Setup app state variables. Can be used in handler functions by doing closures see exchangeAuthorizationCodeCallback
  env := &IdpFeEnv{
    Provider: provider,
    IdpBeClient: idpbeClient,
    HydraConfig: hydraConfig,
  }

  /*hydraClient := NewHydraClient(&oauth2.Config{
    ClientID:     config.IdpFe.ClientId,
    ClientSecret: config.IdpFe.ClientSecret,
    Endpoint:     provider.Endpoint(),
    RedirectURL:  config.IdpFe.PublicCallbackUrl,
    Scopes:       config.IdpFe.RequiredScopes,
  })*/

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
   r.Use(sessions.Sessions(sessionStoreKey, store))

   // Use CSRF on all idp-fe forms.
   adapterCSRF := adapter.Wrap(csrf.Protect([]byte(config.IdpFe.CsrfAuthKey), csrf.Secure(true)))
   // r.Use(adapterCSRF) // Do not use this as it will make csrf tokens for public files aswell which is just extra data going over the wire, no need for that.

   r.Static("/public", "public")
   r.LoadHTMLGlob("views/*")

   ep := r.Group("/")
   ep.Use(adapterCSRF)
   {
     ep.GET("/", showAuthentication(env))
     ep.GET("/authenticate", showAuthentication(env))
     ep.POST("/authenticate", submitAuthentication(env))

     ep.GET("/logout", AuthenticationAndScopesRequired("openid"), showLogout(env))
     ep.POST("/logout", AuthenticationAndScopesRequired("openid"), submitLogout(env))
     ep.GET("/logout-session", showLogoutSession(env))
     ep.POST("/logout-session", submitLogoutSession(env))

     ep.GET("/register", showRegistration(env))
     ep.POST("/register", submitRegistration(env))

     ep.GET("/recover", showRecover(env))
     ep.POST("/recover", submitRecover(env))

     ep.GET("/callback", exchangeAuthorizationCodeCallback(env)) // token exhange endpoint.

     ep.GET("/me", AuthenticationAndScopesRequired("openid"), showProfile(env))
   }

   r.RunTLS(":80", "/srv/certs/idpfe-cert.pem", "/srv/certs/idpfe-key.pem")
}

func StartAuthentication(c *gin.Context) (*url.URL, error) {
  var state string
  session := sessions.Default(c)
  v := session.Get(sessionStateKey)
  if v == nil {
    // No state in session found, so calculate one.
    st := make([]byte, 64) // 64 bytes
    _, err := rand.Read(st)
    if err != nil {
      return &url.URL{}, err
    }
    state = base64.StdEncoding.EncodeToString(st)
    session.Set(sessionStateKey, state)
		session.Save()
    debugLog(logIdpFeApp, "StartAuthentication", "Saved session "+sessionStateKey+": " + state, "")
  } else {
    state = v.(string)
  }

  debugLog(logIdpFeApp, "StartAuthentication", "Using "+sessionStateKey+" param: " + state, "")
  authUrl := hydraConfig.AuthCodeURL(state) //idpfeHydraPublic.AuthCodeURL(state)
  u, err := url.Parse(authUrl)
  return u, err
}

// Gin middleware to secure idp fe endpoints using oauth2
func AuthenticationAndScopesRequired(requiredScopes ...string) gin.HandlerFunc {
  return func(c *gin.Context) {

    debugLog(logIdpFeApp, "AuthenticationAndScopesRequired", "Checking request for bearer token", c.MustGet("RequestId").(string))
    var token *oauth2.Token

    auth := c.Request.Header.Get("Authorization")
    split := strings.SplitN(auth, " ", 2)
    if len(split) == 2 || strings.EqualFold(split[0], "bearer") {
      token = &oauth2.Token{
        AccessToken: split[1],
        TokenType: split[0],
      }
      debugLog(logIdpFeApp, "AuthenticationAndScopesRequired", "Found access token in Authorization: Bearer for request.", "")
    } else {

      debugLog(logIdpFeApp, "AuthenticationAndScopesRequired", "Checking session for token", c.MustGet("RequestId").(string))

      // 2. Check session for access token that is valid, since bearer did not yeild a result
      session := sessions.Default(c)

      debugLog(logIdpFeApp, "AuthenticationAndScopesRequired", "Printing session... ", c.MustGet("RequestId").(string))
      fmt.Println(session.Get(sessionTokenKey))

      v := session.Get(sessionTokenKey)
      if v != nil {
        token = v.(*oauth2.Token)
        debugLog(logIdpFeApp, "AuthenticationAndScopesRequired", "Found access token in idp-fe session store for request.", "")
      }
    }

    // Allow access
    if token.Valid() == true {
      debugLog(logIdpFeApp, "AuthenticationAndScopesRequired", "Valid access token found", c.MustGet("RequestId").(string))

      fmt.Println(token)

      // Questions that need answering before granting access to a protected resource:
      // 1. Is the user or client authenticated? Answered by the process of obtaining an access token.
      // 2. Is the access token expired? Answered by token.Valid(), https://godoc.org/golang.org/x/oauth2#Token.Valid
      // 3. Is the access token granted the required scopes? FIXME: Use introspection or JWT to decide
      // 4. Is the user or client giving the grants in the access token authorized to operate the scopes granted? FIXME: Ask cpbe to determine or use JWT
      // 5. Is the access token revoked? Use idpbe.IsAccessTokenRevoked to decide.

      // TODO: Set the http client to use for this request with the required access token.

      c.Set("user.name", "Marc")
      c.Set("user.email", "marc@cybertron.dk")
      c.Set("user.user", "user-1")
      c.Next() // Grant access
      return;
    }

    debugLog(logIdpFeApp, "AuthenticationAndScopesRequired", "No valid token found", c.MustGet("RequestId").(string))

    // Deny by default, by requiring authentication and authorization.
    initUrl, err := StartAuthentication(c)
    if err != nil {
      c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
      c.Abort()
      return
    }
    c.Redirect(http.StatusFound, initUrl.String())
    c.Abort()
    return
  }
}

func exchangeAuthorizationCodeCallback(env *IdpFeEnv) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    debugLog(logIdpFeApp, "exchangeAuthorizationCodeCallback", "", c.MustGet("RequestId").(string))
    session := sessions.Default(c)
    v := session.Get(sessionStateKey)
    if v == nil {
      c.JSON(http.StatusBadRequest, gin.H{"error": "Request not initiated by idp-fe app. Hint: Missing "+sessionStateKey+" in session"})
      c.Abort()
      return;
    }
    sessionState := v.(string)

    requestState := c.Query("state")
    if requestState == "" {
      c.JSON(http.StatusBadRequest, gin.H{"error": "No state found. Hint: Missing state in query"})
      c.Abort()
      return;
    }

    if requestState != sessionState {
      c.JSON(http.StatusBadRequest, gin.H{"error": "Request did not originate from app. Hint: session state and request state differs"})
      c.Abort()
      return;
    }

    code := c.Query("code")
    if code == "" {
      c.JSON(http.StatusBadRequest, gin.H{"error": "No code to exchange for an access token. Hint: Missing code in query"})
      c.Abort()
      return;
    }

    // Found a code try and exchange it for access token.
    token, err := env.HydraConfig.Exchange(context.Background(), code)
    if err != nil {
      c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    if token.Valid() == true {

      rawIdToken, ok := token.Extra("id_token").(string)
      if !ok {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "No id_token found with access token"})
        c.Abort()
        return
      }

      oidcConfig := &oidc.Config{
        ClientID: config.IdpFe.ClientId,
      }
      verifier := env.Provider.Verifier(oidcConfig)

      idToken, err := verifier.Verify(context.Background(), rawIdToken)
      if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to verify id_token. Hint: " + err.Error()})
        return
      }

      fmt.Println("The access token")
      fmt.Println(token)
      fmt.Println("The id token")
      fmt.Println(idToken.Subject)
      fmt.Println(reflect.TypeOf(idToken))

      session := sessions.Default(c)
      session.Set(sessionTokenKey, token)
      session.Set(sessionIdTokenKey, idToken)
      err = session.Save()
      if err == nil {
        var redirectTo = config.IdpFe.DefaultRedirectUrl // FIXME: Where to redirect to?
        debugLog(logIdpFeApp, "exchangeAuthorizationCodeCallback", "Redirecting to: " + redirectTo, c.MustGet("RequestId").(string))
        c.Redirect(http.StatusFound, redirectTo)
        c.Abort()
        return;
      }

      debugLog(logIdpFeApp, "exchangeAuthorizationCodeCallback", "Failed to save session data: " + err.Error(), c.MustGet("RequestId").(string))
      c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to save session data"})
      c.Abort()
      return
    }

    // Deny by default.
    c.JSON(http.StatusUnauthorized, gin.H{"error": "Exchanged token was invalid. Hint: The timeout on the token might be to short"})
    c.Abort()
    return
  }
  return gin.HandlerFunc(fn)
}

func showProfile(env *IdpFeEnv) gin.HandlerFunc {
  fn := func(c *gin.Context) {
    debugLog(logIdpFeApp, "showProfile", "", c.MustGet("RequestId").(string))

    var idToken *oidc.IDToken
    session := sessions.Default(c)
    idToken = session.Get(sessionIdTokenKey).(*oidc.IDToken)
    if idToken == nil {
      c.HTML(http.StatusNotFound, "me.html", gin.H{"error": "Identity not found"})
      c.Abort()
      return
    }

    // Look up profile information for user.
    request := idpbe.IdentityRequest{
      Id: idToken.Subject,
    }
    profile, err := idpbe.FetchProfile(config.IdpBe.IdentitiesUrl, env.IdpBeClient, request)
    if err != nil {
      c.HTML(http.StatusNotFound, "me.html", gin.H{"error": "Identity not found"})
      c.Abort()
      return
    }

    c.HTML(http.StatusOK, "me.html", gin.H{
      "user": idToken.Subject,
      "name": profile.Name,
      "email": profile.Email,
    })
  }
  return gin.HandlerFunc(fn)
}

func showLogout(env *IdpFeEnv) gin.HandlerFunc {
  fn := func(c *gin.Context) {
    debugLog(logIdpFeApp, "showLogout", "", c.MustGet("RequestId").(string))
    logoutChallenge := c.Query("logout_challenge")
    if logoutChallenge == "" {
      // No logout challenge ask hydra for one.
      c.Redirect(302, config.Hydra.PublicLogoutUrl)
      c.Abort()
      return
    }

    logoutError := c.Query("logout_error")
    c.HTML(200, "logout.html", gin.H{
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "challenge": logoutChallenge,
      "logout_error": logoutError,
    })
  }
  return gin.HandlerFunc(fn)
}

func submitLogout(env *IdpFeEnv) gin.HandlerFunc {
  fn := func(c *gin.Context) {
    debugLog(logIdpFeApp, "submitLogout", "", c.MustGet("RequestId").(string))
    var form authenticationForm
    err := c.Bind(&form)
    if err != nil {
      // Do better error handling in the application.
      c.JSON(400, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    var request = idpbe.LogoutRequest{
      Challenge: form.Challenge,
    }
    logout, err := idpbe.Logout(config.IdpBe.LogoutUrl, env.IdpBeClient, request)
    if err != nil {
      c.JSON(400, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    session := sessions.Default(c)
    session.Clear()
    session.Save()

    c.Redirect(302, logout.RedirectTo)
    c.Abort()
  }
  return gin.HandlerFunc(fn)
}

func showLogoutSession(env *IdpFeEnv) gin.HandlerFunc {
  fn := func(c *gin.Context) {
    debugLog(logIdpFeApp, "showLogoutSession", "", c.MustGet("RequestId").(string))

    c.HTML(200, "logout-session.html", gin.H{
      csrf.TemplateTag: csrf.TemplateField(c.Request),
    })
  }
  return gin.HandlerFunc(fn)
}

func submitLogoutSession(env *IdpFeEnv) gin.HandlerFunc {
  fn := func(c *gin.Context) {
    debugLog(logIdpFeApp, "submitLogoutSession", "", c.MustGet("RequestId").(string))

    session := sessions.Default(c)
    session.Clear()
    session.Save()
    c.Redirect(302, "/me")
    c.Abort()
  }
  return gin.HandlerFunc(fn)
}

func showAuthentication(env *IdpFeEnv) gin.HandlerFunc {
  fn := func(c *gin.Context) {
    debugLog(logIdpFeApp, "showAuthentication", "", c.MustGet("RequestId").(string))

    loginChallenge := c.Query("login_challenge")
    if loginChallenge == "" {
      // User is visiting login page as the first part of the process, probably meaning. Want to view profile or change it.
      // Idp-Fe should ask hydra for a challenge to login
      initUrl, err := StartAuthentication(c)
      if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        c.Abort()
        return
      }
      c.Redirect(http.StatusFound, initUrl.String())
      c.Abort()
      return
    }

    var authenticateRequest = idpbe.AuthenticateRequest{
      Challenge: loginChallenge,
    }
    authenticateResponse, err := idpbe.Authenticate(config.IdpBe.AuthenticateUrl, env.IdpBeClient, authenticateRequest)
    if err != nil {
      c.JSON(400, gin.H{"error": err.Error()})
      c.Abort()
      return
    }
    if authenticateResponse.Authenticated {
      c.Redirect(302, authenticateResponse.RedirectTo)
      c.Abort()
      return
    }
    loginError := c.Query("login_error")
    c.HTML(200, "authenticate.html", gin.H{
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "challenge": loginChallenge,
      "login_error": loginError,
    })
  }
  return gin.HandlerFunc(fn)
}

func showRegistration(env *IdpFeEnv) gin.HandlerFunc {
  fn := func(c *gin.Context) {
    debugLog(logIdpFeApp, "showRegistration", "", c.MustGet("RequestId").(string))
    c.HTML(200, "register.html", nil)
  }
  return gin.HandlerFunc(fn)
}

func showRecover(env *IdpFeEnv) gin.HandlerFunc {
  fn := func(c *gin.Context) {
    debugLog(logIdpFeApp, "showRecovery", "", c.MustGet("RequestId").(string))
    c.HTML(200, "recover.html", nil)
  }
  return gin.HandlerFunc(fn)
}

func submitAuthentication(env *IdpFeEnv) gin.HandlerFunc {
  fn := func(c *gin.Context) {
    debugLog(logIdpFeApp, "submitAuthentication", "", c.MustGet("RequestId").(string))
    var form authenticationForm
    err := c.Bind(&form)

    if err != nil {
      // Do better error handling in the application.
      c.JSON(400, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    // Ask idp-be to authenticate the user
    var authenticateRequest = idpbe.AuthenticateRequest{
      Id: form.Identity,
      Password: form.Password,
      Challenge: form.Challenge,
    }
    authenticateResponse, err := idpbe.Authenticate(config.IdpBe.AuthenticateUrl, env.IdpBeClient, authenticateRequest)
    if err != nil {
      c.JSON(400, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    // User authenticated, redirect
    if authenticateResponse.Authenticated {
      c.Redirect(302, authenticateResponse.RedirectTo)
      c.Abort()
      return
    }

    // Deny by default
    // Failed authentication, retry login challenge.
    retryLoginUrl := "/?login_challenge=" + form.Challenge + "&login_error=Authentication Failure";
    retryUrl, err := url.Parse(retryLoginUrl)
    if err != nil {
      c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
      c.Abort()
      return
    }
    c.Redirect(302, retryUrl.String())
    c.Abort()
  }
  return gin.HandlerFunc(fn)
}

func submitRegistration(env *IdpFeEnv) gin.HandlerFunc {
  fn := func(c *gin.Context) {
    debugLog(logIdpFeApp, "submitRegistration", "", c.MustGet("RequestId").(string))
    var form registrationForm
    c.Bind(&form)
    c.JSON(200, gin.H{
        "id": form.Identity,
        "email": form.Email,
        "password" : form.Password,
        "password_retyped" : form.PasswordRetyped })
  }
  return gin.HandlerFunc(fn)
}

func submitRecover(env *IdpFeEnv) gin.HandlerFunc {
  fn := func(c *gin.Context) {
    debugLog(logIdpFeApp, "submitRecover", "", c.MustGet("RequestId").(string))
    var form recoverForm
    c.Bind(&form)
    c.JSON(200, gin.H{"id": form.Identity })
  }
  return gin.HandlerFunc(fn)
}
