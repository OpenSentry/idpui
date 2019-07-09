package main

import (
  "errors"
  "strings"
  "fmt"
  "net/url"
  "net/http"
  "encoding/base64"
  "encoding/gob"
  "crypto/rand"
  _ "reflect"

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
  "golang-idp-fe/gateway/cpbe"
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
const requestIdKey = "RequestId"

func init() {
  config.InitConfigurations()

  gob.Register(&oauth2.Token{}) // This is required to make session in idp-fe able to persist tokens.
  gob.Register(&oidc.IDToken{})

}

const app = "idp-fe"
func debugLog(app string, event string, msg string, requestId string) {
  if requestId == "" {
    fmt.Println(fmt.Sprintf("[app:%s][event:%s] %s", app, event, msg))
    return;
  }
  fmt.Println(fmt.Sprintf("[app:%s][request-id:%s][event:%s] %s", app, requestId, event, msg))
}

/*var (
  hydraConfig *oauth2.Config
  idpbeConfig *clientcredentials.Config
)*/

/*
type HydraClient struct {
  *http.Client
}
func NewHydraClient(config *oauth2.Config, token *oauth2.Token) *HydraClient {
  ctx := context.Background()
  client := config.Client(ctx, token)
  return &HydraClient{client}
}
*/

type IdpFeEnv struct {
  Provider *oidc.Provider
  IdpBeConfig *clientcredentials.Config
  CpBeConfig *clientcredentials.Config
  HydraConfig *oauth2.Config
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
    Scopes:       []string{"openid"},
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
  env := &IdpFeEnv{
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

     ep.GET("/logout", AuthenticationAndAuthorizationRequired(env, "openid"), showLogout(env))
     ep.POST("/logout", AuthenticationAndAuthorizationRequired(env, "openid"), submitLogout(env))
     ep.GET("/logout-session", showLogoutSession(env))
     ep.POST("/logout-session", submitLogoutSession(env))

     ep.GET("/register", showRegistration(env))
     ep.POST("/register", submitRegistration(env))

     ep.GET("/recover", showRecover(env))
     ep.POST("/recover", submitRecover(env))

     ep.GET("/callback", exchangeAuthorizationCodeCallback(env)) // token exhange endpoint.

     ep.GET("/me", AuthenticationAndAuthorizationRequired(env, "openid"), showProfile(env))

     ep.GET("/consent", AuthenticationAndAuthorizationRequired(env, "openid"), showConsent(env))
     ep.POST("/consent", AuthenticationAndAuthorizationRequired(env, "openid"), submitConsent(env))
   }

   r.RunTLS(":" + config.Self.Port, "/srv/certs/idpfe-cert.pem", "/srv/certs/idpfe-key.pem")
}

func StartAuthentication(env *IdpFeEnv, c *gin.Context) (*url.URL, error) {
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
    debugLog(app, "StartAuthentication", "Saved session "+sessionStateKey+": " + state, "")
  } else {
    state = v.(string)
  }

  debugLog(app, "StartAuthentication", "Using "+sessionStateKey+" param: " + state, "")
  authUrl := env.HydraConfig.AuthCodeURL(state) //idpfeHydraPublic.AuthCodeURL(state)
  u, err := url.Parse(authUrl)
  return u, err
}

const accessTokenKey = "access_token"
const idTokenKey = "id_token"

// # Authentication and Authorization
// Gin middleware to secure idp fe endpoints using oauth2.
//
// ## QTNA - Questions that need answering before granting access to a protected resource
// 1. Is the user or client authenticated? Answered by the process of obtaining an access token.
// 2. Is the access token expired?
// 3. Is the access token granted the required scopes?
// 4. Is the user or client giving the grants in the access token authorized to operate the scopes granted?
// 5. Is the access token revoked?
func AuthenticationAndAuthorizationRequired(env *IdpFeEnv, requiredScopes ...string) gin.HandlerFunc {
  fn := func(c *gin.Context) {
    var requestId string = c.MustGet(requestIdKey).(string)
    debugLog(app, "AuthenticationAndAuthorizationRequired", "", requestId)

    // Authentication
    token, err := authenticationRequired(env, c)
    if err != nil {
      // Require authentication to access resources. Init oauth2 Authorization code flow with idpfe as the client.
      debugLog(app, "AuthenticationAndAuthorizationRequired", "Error: " + err.Error(), requestId)
      initUrl, err := StartAuthentication(env, c)
      if err != nil {
        debugLog(app, "AuthenticationAndAuthorizationRequired", "Error: " + err.Error(), requestId)
        c.HTML(http.StatusInternalServerError, "", gin.H{"error": err.Error()})
        c.Abort()
        return
      }
      c.Redirect(http.StatusFound, initUrl.String())
      c.Abort()
      return
    }
    c.Set(accessTokenKey, token) // Authenticated, so use it forward.

    // Authorization
    grantedScopes, err := authorizationRequired(env, c, requiredScopes)
    if err != nil {
      debugLog(app, "AuthenticationAndAuthorizationRequired", "Error: " + err.Error(), requestId)
      c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
      c.Abort()
      return
    }
    fmt.Println(grantedScopes)

    // FIXME: Find IdToken for access token.
    idToken := &oauth2.Token{}
    c.Set(idTokenKey, idToken) // Authorized

    c.Next() // Authentication and authorization successful, continue.
    return
  }
  return gin.HandlerFunc(fn)
}

func authenticationRequired(env *IdpFeEnv, c *gin.Context) (*oauth2.Token, error) {
  var requestId string = c.MustGet(requestIdKey).(string)
  debugLog(app, "authenticationRequired", "Checking Authorization: Bearer <token> in request", requestId)

  var token *oauth2.Token
  auth := c.Request.Header.Get("Authorization")
  split := strings.SplitN(auth, " ", 2)
  if len(split) == 2 || strings.EqualFold(split[0], "bearer") {
    debugLog(app, "authenticationRequired", "Authorization: Bearer <token> found for request.", requestId)
    token = &oauth2.Token{
      AccessToken: split[1],
      TokenType: split[0],
    }
  } else {
    debugLog(app, "authenticationRequired", "Checking Session <token> in request", requestId)
    session := sessions.Default(c)
    v := session.Get(sessionTokenKey)
    if v != nil {
      token = v.(*oauth2.Token)
      debugLog(app, "authenticationRequired", "Session <token> found in request", requestId)
    }
  }

  // See #2 of QTNA
  // https://godoc.org/golang.org/x/oauth2#Token.Valid
  if token.Valid() == true {
    debugLog(app, "authenticationRequired", "Valid access token", requestId)

    // See #5 of QTNA
    // FIXME: Call token revoked list to check if token is revoked.
    debugLog(app, "authenticationRequired", "Missing implementation of QTNA #5 - Is the access token revoked?", requestId)

    return token, nil
  }

  // Deny by default
  debugLog(app, "authenticationRequired", "Missing or invalid access token", requestId)
  return &oauth2.Token{}, errors.New("Missing or invalid access token")
}

func authorizationRequired(env *IdpFeEnv, c *gin.Context, requiredScopes []string) ([]string, error) {
  var requestId string = c.MustGet(requestIdKey).(string)
  debugLog(app, "authorizationRequired", "Checking required scopes for request", requestId)

  // See #3 of QTNA
  debugLog(app, "authorizationRequired", "Missing implementation of QTNA #3 - Is the access token granted the required scopes?", requestId)
  cpbeClient := cpbe.NewCpBeClient(env.CpBeConfig)
  grantedScopes, err := cpbe.IsRequiredScopesGrantedForToken(config.CpBe.AuthorizationsUrl, cpbeClient, requiredScopes)
  if err != nil {
    return nil, err
  }

  // See #4 of QTNA
  // FIXME: Is user who granted the scopes allow to use the scopes (check cpbe model for what user is allowed to do.)
  debugLog(app, "authorizationRequired", "Missing implementation of QTNA #4 - Is the user or client giving the grants in the access token authorized to operate the scopes granted?", requestId)

  strGrantedScopes := strings.Join(grantedScopes, ",")
  debugLog(app, "authorizationRequired", "Valid scopes: " + strGrantedScopes, requestId)
  return grantedScopes, nil
}

func exchangeAuthorizationCodeCallback(env *IdpFeEnv) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    debugLog(app, "exchangeAuthorizationCodeCallback", "", c.MustGet("RequestId").(string))
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

      session := sessions.Default(c)
      session.Set(sessionTokenKey, token)
      session.Set(sessionIdTokenKey, idToken)
      err = session.Save()
      if err == nil {
        var redirectTo = config.IdpFe.DefaultRedirectUrl // FIXME: Where to redirect to?
        debugLog(app, "exchangeAuthorizationCodeCallback", "Redirecting to: " + redirectTo, c.MustGet("RequestId").(string))
        c.Redirect(http.StatusFound, redirectTo)
        c.Abort()
        return;
      }

      debugLog(app, "exchangeAuthorizationCodeCallback", "Failed to save session data: " + err.Error(), c.MustGet("RequestId").(string))
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
    debugLog(app, "showProfile", "", c.MustGet("RequestId").(string))

    // NOTE: Maybe session is not a good way to do this.
    // 1. The user access /me with a browser and the access token / id token is stored in a session as we cannot make the browser redirect with Authentication: Bearer <token>
    // 2. The user is using something that supplies the access token and id token directly in the headers. (aka. no need for the session)
    var idToken *oidc.IDToken
    session := sessions.Default(c)
    idToken = session.Get(sessionIdTokenKey).(*oidc.IDToken)
    if idToken == nil {
      c.HTML(http.StatusNotFound, "me.html", gin.H{"error": "Identity not found"})
      c.Abort()
      return
    }

    idpbeClient := idpbe.NewIdpBeClient(env.IdpBeConfig)

    // Look up profile information for user.
    request := idpbe.IdentityRequest{
      Id: idToken.Subject,
    }
    profile, err := idpbe.FetchProfile(config.IdpBe.IdentitiesUrl, idpbeClient, request)
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

func showConsent(env *IdpFeEnv) gin.HandlerFunc {
  fn := func(c *gin.Context) {
    debugLog(app, "showConsent", "", c.MustGet("RequestId").(string))
    c.HTML(http.StatusOK, "consent.html", gin.H{
      csrf.TemplateTag: csrf.TemplateField(c.Request),
    })
  }
  return gin.HandlerFunc(fn)
}

func submitConsent(env *IdpFeEnv) gin.HandlerFunc {
  fn := func(c *gin.Context) {
    debugLog(app, "submitConsent", "", c.MustGet("RequestId").(string))

    var idToken *oidc.IDToken
    session := sessions.Default(c)
    idToken = session.Get(sessionIdTokenKey).(*oidc.IDToken)
    if idToken == nil {
      c.HTML(http.StatusNotFound, "consent.html", gin.H{"error": "Identity not found"})
      c.Abort()
      return
    }

    idpbeClient := idpbe.NewIdpBeClient(env.IdpBeConfig)

    request := idpbe.RevokeConsentRequest{
      Id: idToken.Subject,
    }
    r, err := idpbe.RevokeConsent("fixme", idpbeClient, request)
    if err != nil {
      c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
      c.Abort()
      return
    }
    c.JSON(http.StatusOK, gin.H{"status": r})
  }
  return gin.HandlerFunc(fn)
}


func showLogout(env *IdpFeEnv) gin.HandlerFunc {
  fn := func(c *gin.Context) {
    debugLog(app, "showLogout", "", c.MustGet("RequestId").(string))
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
    debugLog(app, "submitLogout", "", c.MustGet("RequestId").(string))
    var form authenticationForm
    err := c.Bind(&form)
    if err != nil {
      // Do better error handling in the application.
      c.JSON(400, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    idpbeClient := idpbe.NewIdpBeClient(env.IdpBeConfig)

    var request = idpbe.LogoutRequest{
      Challenge: form.Challenge,
    }
    logout, err := idpbe.Logout(config.IdpBe.LogoutUrl, idpbeClient, request)
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
    debugLog(app, "showLogoutSession", "", c.MustGet("RequestId").(string))

    c.HTML(200, "logout-session.html", gin.H{
      csrf.TemplateTag: csrf.TemplateField(c.Request),
    })
  }
  return gin.HandlerFunc(fn)
}

func submitLogoutSession(env *IdpFeEnv) gin.HandlerFunc {
  fn := func(c *gin.Context) {
    debugLog(app, "submitLogoutSession", "", c.MustGet("RequestId").(string))

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
    debugLog(app, "showAuthentication", "", c.MustGet("RequestId").(string))

    loginChallenge := c.Query("login_challenge")
    if loginChallenge == "" {
      // User is visiting login page as the first part of the process, probably meaning. Want to view profile or change it.
      // Idp-Fe should ask hydra for a challenge to login
      initUrl, err := StartAuthentication(env, c)
      if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        c.Abort()
        return
      }
      c.Redirect(http.StatusFound, initUrl.String())
      c.Abort()
      return
    }

    idpbeClient := idpbe.NewIdpBeClient(env.IdpBeConfig)

    var authenticateRequest = idpbe.AuthenticateRequest{
      Challenge: loginChallenge,
    }
    authenticateResponse, err := idpbe.Authenticate(config.IdpBe.AuthenticateUrl, idpbeClient, authenticateRequest)
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
    debugLog(app, "showRegistration", "", c.MustGet("RequestId").(string))
    c.HTML(200, "register.html", nil)
  }
  return gin.HandlerFunc(fn)
}

func showRecover(env *IdpFeEnv) gin.HandlerFunc {
  fn := func(c *gin.Context) {
    debugLog(app, "showRecovery", "", c.MustGet("RequestId").(string))
    c.HTML(200, "recover.html", nil)
  }
  return gin.HandlerFunc(fn)
}

func submitAuthentication(env *IdpFeEnv) gin.HandlerFunc {
  fn := func(c *gin.Context) {
    debugLog(app, "submitAuthentication", "", c.MustGet("RequestId").(string))
    var form authenticationForm
    err := c.Bind(&form)

    if err != nil {
      // Do better error handling in the application.
      c.JSON(400, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    idpbeClient := idpbe.NewIdpBeClient(env.IdpBeConfig)

    // Ask idp-be to authenticate the user
    var authenticateRequest = idpbe.AuthenticateRequest{
      Id: form.Identity,
      Password: form.Password,
      Challenge: form.Challenge,
    }
    authenticateResponse, err := idpbe.Authenticate(config.IdpBe.AuthenticateUrl, idpbeClient, authenticateRequest)
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
    debugLog(app, "submitRegistration", "", c.MustGet("RequestId").(string))
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
    debugLog(app, "submitRecover", "", c.MustGet("RequestId").(string))
    var form recoverForm
    c.Bind(&form)
    c.JSON(200, gin.H{"id": form.Identity })
  }
  return gin.HandlerFunc(fn)
}
