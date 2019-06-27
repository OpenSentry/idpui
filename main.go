package main

import (
  "strings"
  "fmt"
  "net/url"
  "net/http"
  "golang.org/x/oauth2"
  "golang.org/x/oauth2/clientcredentials"
  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"
  "github.com/gwatts/gin-adapter"
  "golang-idp-fe/config"
  "golang-idp-fe/gateway/idpbe"
  "golang-idp-fe/gateway/idpfe"
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
	oauth2Hydra *oauth2.Config
  oauth2HydraPublic *oauth2.Config
  idpbeClient *http.Client
)

func init() {
  config.InitConfigurations()

  var HydraEndpoint = oauth2.Endpoint{
  	AuthURL:  config.Hydra.AuthenticateUrl,
  	TokenURL: config.Hydra.TokenUrl,
  }

  oauth2Hydra = &oauth2.Config{
  	RedirectURL:  config.IdpFe.DefaultRedirectUrl,
  	ClientID:     config.IdpFe.ClientId,
  	ClientSecret: config.IdpFe.ClientSecret,
  	Scopes:       config.IdpFe.RequiredScopes,
  	Endpoint:     HydraEndpoint,
  }

  var HydraPublicEndpoint = oauth2.Endpoint{
    AuthURL:  config.Hydra.PublicAuthenticateUrl,
    TokenURL: config.Hydra.PublicTokenUrl,
  }

  oauth2HydraPublic = &oauth2.Config{
    RedirectURL:  config.IdpFe.DefaultRedirectUrl,
    ClientID:     config.IdpFe.ClientId,
    ClientSecret: config.IdpFe.ClientSecret,
    Scopes:       config.IdpFe.RequiredScopes,
    Endpoint:     HydraPublicEndpoint,
  }

}

func main() {

   // Initialize the idp-be http client with client credentials token for use in the API.
   var idpbeClientCredentialsConfig *clientcredentials.Config = &clientcredentials.Config{
     ClientID:     config.IdpFe.ClientId,
     ClientSecret: config.IdpFe.ClientSecret,
     TokenURL:     config.Hydra.TokenUrl,
     Scopes: []string{"openid", "idpbe.authenticate"},
     EndpointParams: url.Values{"audience": {"idpbe"}},
     AuthStyle: 2, // https://godoc.org/golang.org/x/oauth2#AuthStyle
   }
   idpbeToken, err := idpfe.RequestAccessTokenForIdpBe(idpbeClientCredentialsConfig)
   if err != nil {
     fmt.Println("Unable to aquire idpbe access token. Error: " + err.Error())
     return
   }
   fmt.Println(idpbeToken) // FIXME Do not log this!!
   idpbeClient = idpbeClientCredentialsConfig.Client(oauth2.NoContext)

   r := gin.Default()

   // Use CSRF on all idp-fe forms.
   fmt.Println("Using insecure CSRF for devlopment. Do not do this in production")
   adapterCSRF := adapter.Wrap(csrf.Protect([]byte(config.IdpFe.CsrfAuthKey), csrf.Secure(false)))
   // r.Use(adapterCSRF) // Do not use this as it will make csrf tokens for public files aswell which is just extra data going over the wire, no need for that.

   r.Static("/public", "public")
   r.LoadHTMLGlob("views/*")

   ep := r.Group("/")
   ep.Use(adapterCSRF)
   ep.Use(unmarshalBearerToken())
   {
     ep.GET("/", getAuthenticationHandler)
     ep.GET("/authenticate", getAuthenticationHandler)
     ep.POST("/authenticate", postAuthenticationHandler)

     ep.GET("/logout", getLogoutHandler)
     ep.POST("/logout", postLogoutHandler)

     ep.GET("/register", getRegisterHandler)
     ep.POST("/register", postRegistrationHandler)

     ep.GET("/recover", getRecoverHandler)
     ep.POST("/recover", postRecoverHandler)

     ep.GET("/me", AuthenticationAndScopesRequired("openid"), getProfileHandler)
   }

   r.Run() // defaults to :8080, uses env PORT if set
}

// Look for a bearer token and unmarshal it into the gin context for the request for later use.
func unmarshalBearerToken() gin.HandlerFunc {
  return func(c *gin.Context) {
    auth := c.Request.Header.Get("Authorization")
    split := strings.SplitN(auth, " ", 2)
    if len(split) != 2 || !strings.EqualFold(split[0], "bearer") {
      // No bearer token, so continue
      c.Next()
      return
    }

    token := &oauth2.Token{
      AccessToken: split[1],
      TokenType: split[0],
    }
    c.Set("bearer_token", token)
    c.Next()
  }
}

// Gin middleware to secure idp fe endpoints using oauth2
func AuthenticationAndScopesRequired(scopes ...string) gin.HandlerFunc {
  return func(c *gin.Context) {

    // Authentication and authorization questions that need answering before granting access to resource.
    // These need to live in idp-be?
    isTokenValid := false
    //isTokenRevoked := false
    //isUserAuthenticated := false
    //isUserAuthorized := false
    //isRequiredScopesGranted := false
    //isUserAllowedToUseGrantedScopes := false

    bearerToken, tokenExists := c.Get("bearer_token")
    if ( tokenExists ) {

      // Found a bearer token use that if possible.
      token := bearerToken.(*oauth2.Token)

      isTokenValid = token.Valid()
      if isTokenValid == true {
        c.Set("access_token", token.AccessToken)
        c.Next() // Grant access
        return;
      }
    }

    // No bearer token, look for code to exchange for token.
    code := c.Query("code")
    if code != "" {

      // Check that the state request originated from this app. ?!!
      /*state := c.Query("state")
      if state != "" {
        initialState := "pleasechangeme"
        if state != initialState {
          // Code to token exchange was not initiated by our initial request. Deny!
          c.JSON(http.StatusUnauthorized, gin.H{"error": "Token exchange request not initiated by initial request. Access Denied"})
          c.Abort()
          return
        }
      }*/

      // Found a code try and exchange it for access token.
      token, err := oauth2Hydra.Exchange(oauth2.NoContext, code)
      if err != nil {
        fmt.Println(err) // What to do here?
        c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
        c.Abort()
        return
      }

      isTokenValid = token.Valid()
      if isTokenValid == true {
        c.Set("access_token", token.AccessToken)
        c.Next() // Grant access
        return;
      }
	  }

    // Deny by default - by requiring authentication

    var state string = "pleasechangeme"
    url := oauth2HydraPublic.AuthCodeURL(state)
    c.Redirect(http.StatusTemporaryRedirect, url)
    c.Abort()
    return
    // FIXME: We need to ask the app session state to store the initial state in a session, so we can check it after redirect chain is done. This requires a session, but hydra said we did not need it!
    /*redirectUrl := config.IdpFe.PublicUrl + c.Request.URL.String()
    var state = "pleasechangeme" // Calculate this
    var url = config.Hydra.PublicAuthenticateUrl + "?client_id=idp-fe&scope=openid&response_type=code&state="+state+"&redirect_uri=" + redirectUrl
    c.Redirect(302, url)
    c.Abort()*/
  }
}

func getProfileHandler(c *gin.Context) {
  var err error
  var profile idpfe.Profile

  profile, err = idpfe.FetchProfileForContext(c);
  if err == nil {
    fmt.Println(profile)
    c.HTML(200, "me.html", gin.H{
      "user": profile.Id,
      "name": profile.Name,
      "email": profile.Email,
    })
    return
  }

  // Deny by default
  c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
  c.Abort()
}

func getLogoutHandler(c *gin.Context) {
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
}

func getAuthenticationHandler(c *gin.Context) {
    loginChallenge := c.Query("login_challenge")

    // User is visiting login page as the first part of the process, probably meaning. Want to view profile or change it.
    // Idp-Fe should ask hydra for a challenge to login
    if loginChallenge == "" {
      var state = "pleasechangeme"
      url := oauth2HydraPublic.AuthCodeURL(state)
      c.Redirect(http.StatusTemporaryRedirect, url)

      /*var url = config.Hydra.PublicAuthenticateUrl + "?client_id=idp-fe&scope=openid&response_type=code&state="+state+"&redirect_uri=" + config.IdpFe.DefaultRedirectUrl
      c.Redirect(302, url)*/
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
    c.HTML(200, "register.html", nil)
}

func getRecoverHandler(c *gin.Context) {
    c.HTML(200, "recover.html", nil)
}

func postLogoutHandler(c *gin.Context) {
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
  logoutResponse, err := idpbe.Logout(config.IdpBe.LogoutUrl, logoutRequest)
  if err != nil {
    c.JSON(400, gin.H{"error": err.Error()})
    c.Abort()
    return
  }

  c.Redirect(302, logoutResponse.RedirectTo)
  c.Abort()
}

func postAuthenticationHandler(c *gin.Context) {
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
    var form registrationForm
    c.Bind(&form)
    c.JSON(200, gin.H{
        "id": form.Identity,
        "email": form.Email,
        "password" : form.Password,
        "password_retyped" : form.PasswordRetyped })
}

func postRecoverHandler(c *gin.Context) {
    var form recoverForm
    c.Bind(&form)
    c.JSON(200, gin.H{
        "id": form.Identity })
}
