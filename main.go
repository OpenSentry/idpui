package main

import (
  "strings"
  "fmt"
  "net/url"
  "net/http"
  "encoding/base64"
  "encoding/gob"
  "crypto/rand"

  "golang.org/x/oauth2"
  "golang.org/x/oauth2/clientcredentials"

  "github.com/gin-gonic/gin"
  "github.com/gin-contrib/sessions"
  "github.com/gin-contrib/sessions/cookie"
  "github.com/gorilla/csrf"
  "github.com/gwatts/gin-adapter"
  "github.com/atarantini/ginrequestid"

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

var (
  idpfeHydra *oauth2.Config
  idpfeHydraPublic *oauth2.Config
  idpbeClient *http.Client
)

const sessionStoreKey = "idpfe"
const sessionTokenKey = "token"
const sessionStateKey = "state"

func init() {
  config.InitConfigurations()

  gob.Register(&oauth2.Token{}) // This is required to make session in idp-fe able to persist tokens.

  var HydraEndpoint = oauth2.Endpoint{
    AuthURL:  config.Hydra.AuthenticateUrl,
    TokenURL: config.Hydra.TokenUrl,
  }

  idpfeHydra = &oauth2.Config{
    RedirectURL:  config.IdpFe.PublicCallbackUrl,
    ClientID:     config.IdpFe.ClientId,
    ClientSecret: config.IdpFe.ClientSecret,
    Scopes:       config.IdpFe.RequiredScopes,
    Endpoint:     HydraEndpoint,
  }

  var HydraPublicEndpoint = oauth2.Endpoint{
    AuthURL:  config.Hydra.PublicAuthenticateUrl,
    TokenURL: config.Hydra.PublicTokenUrl,
  }

  idpfeHydraPublic = &oauth2.Config{
    RedirectURL:  config.IdpFe.PublicCallbackUrl,
    ClientID:     config.IdpFe.ClientId,
    ClientSecret: config.IdpFe.ClientSecret,
    Scopes:       config.IdpFe.RequiredScopes,
    Endpoint:     HydraPublicEndpoint,
  }

  // Initialize the idp-be http client with client credentials token for use in the API.
  var idpbeClientCredentialsConfig *clientcredentials.Config = &clientcredentials.Config{
    ClientID:     config.IdpFe.ClientId,
    ClientSecret: config.IdpFe.ClientSecret,
    TokenURL:     config.Hydra.TokenUrl,
    Scopes: []string{"openid", "idpbe.authenticate"},
    EndpointParams: url.Values{"audience": {"idpbe"}},
    AuthStyle: 2, // https://godoc.org/golang.org/x/oauth2#AuthStyle
  }

  idpbeToken, err := idpbeClientCredentialsConfig.Token(oauth2.NoContext)
  if err != nil {
    debugLog(logIdpFeApp, "init", "Unable to aquire idpbe access token. Error: " + err.Error(), "")
    return
  }
  debugLog(logIdpFeApp, "init", "Logging access token to idp-be. Do not do this in production", "")
  fmt.Println(idpbeToken) // FIXME Do not log this!!
  idpbeClient = idpbeClientCredentialsConfig.Client(oauth2.NoContext)

}

const logIdpFeApp = "idp-fe"
func debugLog(app string, event string, msg string, requestId string) {
  if requestId == "" {
    fmt.Println(fmt.Sprintf("[app:%s][event:%s] %s", app, event, msg))
    return;
  }
  fmt.Println(fmt.Sprintf("[app:%s][request-id:%s][event:%s] %s", app, requestId, event, msg))
}

func main() {
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

   //r.Use(logRequest())

   // Use CSRF on all idp-fe forms.
   adapterCSRF := adapter.Wrap(csrf.Protect([]byte(config.IdpFe.CsrfAuthKey), csrf.Secure(true)))
   // r.Use(adapterCSRF) // Do not use this as it will make csrf tokens for public files aswell which is just extra data going over the wire, no need for that.

   r.Static("/public", "public")
   r.LoadHTMLGlob("views/*")

   ep := r.Group("/")
   ep.Use(adapterCSRF)
   {
     ep.GET("/", getAuthenticationHandler)
     ep.GET("/authenticate", getAuthenticationHandler)
     ep.POST("/authenticate", postAuthenticationHandler)

     ep.GET("/logout", AuthenticationAndScopesRequired("openid"), getLogoutHandler)
     ep.POST("/logout", AuthenticationAndScopesRequired("openid"), postLogoutHandler)

     ep.GET("/register", getRegisterHandler)
     ep.POST("/register", postRegistrationHandler)

     ep.GET("/recover", getRecoverHandler)
     ep.POST("/recover", postRecoverHandler)

     ep.GET("/callback", getCallbackHandler) // token exhange endpoint.

     ep.GET("/me", AuthenticationAndScopesRequired("openid"), getProfileHandler)
   }

   r.RunTLS(":" + config.Self.Port, "/srv/certs/idpfe-cert.pem", "/srv/certs/idpfe-key.pem")
   //r.Run() // defaults to :8080, uses env PORT if set
}

func logRequest() gin.HandlerFunc {
  return func(c *gin.Context) {
    debugLog(logIdpFeApp, "logRequest", "Logging all requests. Do not do this in production it will leak tokens", "")
    fmt.Println(c.Request)
    c.Next()
  }
}

func GenerateRandomBytes(n int) ([]byte, error) {
  b := make([]byte, n)
  _, err := rand.Read(b)
  // Note that err == nil only if we read len(b) bytes.
  if err != nil {
    return nil, err
  }
  return b, nil
}

func StartAuthentication(c *gin.Context) (*url.URL, error) {
  var state string
  session := sessions.Default(c)
  v := session.Get(sessionStateKey)
  if v == nil {
    // No state in session found, so calculate one.
    st, err := GenerateRandomBytes(32)
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
  authUrl := idpfeHydraPublic.AuthCodeURL(state)
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
      c.Set("user.user", "wraix")
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

func getCallbackHandler(c *gin.Context) {
  debugLog(logIdpFeApp, "getCallbackHandler", "", c.MustGet("RequestId").(string))
  session := sessions.Default(c)
  v := session.Get(sessionStateKey)
  if v == nil {
    c.JSON(http.StatusUnauthorized, gin.H{"error": "Request not initiated by idp-fe app. Hint: Missing "+sessionStateKey+" in session"})
    c.Abort()
    return;
  }
  sessionState := v.(string)

  requestState := c.Query("state")
  if requestState == "" {
    c.JSON(http.StatusUnauthorized, gin.H{"error": "No state found. Hint: Missing state in query"})
    c.Abort()
    return;
  }

  if requestState != sessionState {
    c.JSON(http.StatusUnauthorized, gin.H{"error": "Request did not originate from app. Hint: session state and request state differs"})
    c.Abort()
    return;
  }

  code := c.Query("code")
  if code == "" {
    c.JSON(http.StatusUnauthorized, gin.H{"error": "No code to exchange for an access token. Hint: Missing code in query"})
    c.Abort()
    return;
  }

  // Found a code try and exchange it for access token.
  token, err := idpfeHydra.Exchange(oauth2.NoContext, code)
  if err != nil {
    c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
    c.Abort()
    return
  }

  if token.Valid() == true {

    session := sessions.Default(c)
    session.Set(sessionTokenKey, token)
    err := session.Save()
    if err == nil {
      var redirectTo = config.IdpFe.DefaultRedirectUrl // FIXME: Where to redirect to?
      debugLog(logIdpFeApp, "getCallbackHandler", "Redirecting to: " + redirectTo, c.MustGet("RequestId").(string))
      c.Redirect(http.StatusFound, redirectTo)
      c.Abort()
      return;
    }

    debugLog(logIdpFeApp, "getCallbackHandler", "Failed to save session data: " + err.Error(), c.MustGet("RequestId").(string))
    c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to save session data"})
    c.Abort()
    return
  }

  // Deny by default.
  c.JSON(http.StatusUnauthorized, gin.H{"error": "Exchanged token was invalid. Hint: The timeout on the token might be to short"})
  c.Abort()
  return;
}

func getProfileHandler(c *gin.Context) {
  debugLog(logIdpFeApp, "getProfileHandler", "", c.MustGet("RequestId").(string))

  user, userExists := c.Get("user.user")
  if userExists == false {
    c.HTML(http.StatusUnauthorized, "unauthorized.html", gin.H{
      "error": "No user found",
    })
    c.Abort()
    return
  }

  fmt.Println(user)

/*
  session := sessions.Default(c)
  t := session.Get(sessionTokenKey)
  if t == nil {
    c.HTML(http.StatusUnauthorized, "unauthorized.html", gin.H{
      "error": "Missing access token",
    })
    c.Abort()
    return
  }

  debugLog(logIdpFeApp, "getProfileHandler", "Accessed profile using token:", c.MustGet("RequestId").(string))
  fmt.Println(t)*/

/*
  userClient := token.Client()

  request := idpbe.IdentityRequest{
  }
  profile, err = idpbe.FetchProfile(config.IdpBe.IdentitiesUrl, userClient, request);
  if err == nil {
    fmt.Println(profile)
    c.HTML(200, "me.html", gin.H{
      "user": profile.Id,
      "name": profile.Name,
      "email": profile.Email,
    })
    c.Abort()
    return
  }*/

  c.HTML(http.StatusOK, "me.html", gin.H{
    "user": user,
  })
}

func getLogoutHandler(c *gin.Context) {
  debugLog(logIdpFeApp, "getLogoutHandler", "", c.MustGet("RequestId").(string))

  logoutChallenge := c.Query("logout_challenge")
  if logoutChallenge == "" {
    var url = config.Hydra.PublicLogoutUrl
    c.Redirect(302, url)
    c.Abort()
    return
  }

  logoutError := c.Query("logout_error")
  c.HTML(200, "logout.html", gin.H{
    csrf.TemplateTag: csrf.TemplateField(c.Request),
    "challenge": logoutChallenge,
    "logout_error": logoutError,
  })
  c.Abort()
}

func getAuthenticationHandler(c *gin.Context) {
  debugLog(logIdpFeApp, "getAuthenticationHandler", "", c.MustGet("RequestId").(string))

    loginChallenge := c.Query("login_challenge")

    // User is visiting login page as the first part of the process, probably meaning. Want to view profile or change it.
    // Idp-Fe should ask hydra for a challenge to login
    if loginChallenge == "" {
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

func getRegisterHandler(c *gin.Context) {
  debugLog(logIdpFeApp, "getRegisterHandler", "", c.MustGet("RequestId").(string))
  c.HTML(200, "register.html", nil)
  c.Abort()
}

func getRecoverHandler(c *gin.Context) {
  debugLog(logIdpFeApp, "getRecoverHandler", "", c.MustGet("RequestId").(string))
  c.HTML(200, "recover.html", nil)
  c.Abort()
}

func postLogoutHandler(c *gin.Context) {
  debugLog(logIdpFeApp, "postLogoutHandler", "", c.MustGet("RequestId").(string))
  var form authenticationForm
  err := c.Bind(&form)
  if err != nil {
    // Do better error handling in the application.
    c.JSON(400, gin.H{"error": err.Error()})
    c.Abort()
    return
  }

  var logoutRequest = idpbe.LogoutRequest{
    Challenge: form.Challenge,
  }
  logoutResponse, err := idpbe.Logout(config.IdpBe.LogoutUrl, idpbeClient, logoutRequest)
  if err != nil {
    c.JSON(400, gin.H{"error": err.Error()})
    c.Abort()
    return
  }

  session := sessions.Default(c)
  session.Clear()
  session.Save()

  c.Redirect(302, logoutResponse.RedirectTo)
  c.Abort()
}

func postAuthenticationHandler(c *gin.Context) {
    debugLog(logIdpFeApp, "postAuthenticationHandler", "", c.MustGet("RequestId").(string))
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
      c.JSON(400, gin.H{"error": err.Error()})
      c.Abort()
      return
    }
    c.Redirect(302, retryUrl.String())
    c.Abort()
}

func postRegistrationHandler(c *gin.Context) {
    debugLog(logIdpFeApp, "postRegistrationHandler", "", c.MustGet("RequestId").(string))
    var form registrationForm
    c.Bind(&form)
    c.JSON(200, gin.H{
        "id": form.Identity,
        "email": form.Email,
        "password" : form.Password,
        "password_retyped" : form.PasswordRetyped })
    c.Abort()
}

func postRecoverHandler(c *gin.Context) {
    debugLog(logIdpFeApp, "postRecoverHandler", "", c.MustGet("RequestId").(string))
    var form recoverForm
    c.Bind(&form)
    c.JSON(200, gin.H{"id": form.Identity })
    c.Abort()
}
