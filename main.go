package main

import (
    "golang-idp-fe/config"
    "golang-idp-fe/interfaces"
    "golang-idp-fe/gateway/idpbe"
    "github.com/gin-gonic/gin"
    "github.com/gorilla/csrf"
    "github.com/gwatts/gin-adapter"
    "fmt"
    "net/url"
    "net/http"
	  "strings"
    "golang.org/x/oauth2"
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
	hydraOauthConfig *oauth2.Config
)

func init() {
  config.InitConfigurations()

  var HydraEndpoint = oauth2.Endpoint{
  	AuthURL:  config.Hydra.AuthenticateUrl,
  	TokenURL: config.Hydra.TokenUrl,
  }

  hydraOauthConfig = &oauth2.Config{
  	RedirectURL:  config.IdpFe.DefaultRedirectUrl,
  	ClientID:     config.IdpFe.ClientId,
  	ClientSecret: config.IdpFe.ClientSecret,
  	Scopes:       config.IdpFe.RequiredScopes,
  	Endpoint:     HydraEndpoint,
  }

}


func main() {
    r := gin.Default()

    // Use CSRF on all our forms.
    fmt.Println("Using insecure CSRF for devlopment. Do not do this in production")
    adapterCSRF := adapter.Wrap(csrf.Protect([]byte(config.IdpFe.CsrfAuthKey), csrf.Secure(false)))
    // r.Use(adapterCSRF) // Do not use this as it will make csrf tokens for public files aswell which is just extra data going over the wire, no need for that.

    r.Static("/public", "public")

    r.LoadHTMLGlob("views/*")

    bearer := r.Group("/")
    bearer.Use(unmarshalBearerToken())
    {
      bearer.GET("/", adapterCSRF, getAuthenticationHandler)
      bearer.GET("/authenticate", adapterCSRF, getAuthenticationHandler)
      bearer.POST("/authenticate", adapterCSRF, postAuthenticationHandler)

      bearer.GET("/logout", adapterCSRF, getLogoutHandler)
      bearer.POST("/logout", adapterCSRF, postLogoutHandler)

      bearer.GET("/register", adapterCSRF, getRegisterHandler)
      bearer.POST("/register", adapterCSRF, postRegistrationHandler)

      bearer.GET("/recover", adapterCSRF, getRecoverHandler)
      bearer.POST("/recover", adapterCSRF, postRecoverHandler)

      bearer.GET("/me", AuthenticationAndScopesRequired("openid"), getProfileHandler)

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

      // Found an bearer token use that if possible.
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

      // Found a code try and exchange it for access token.
      token, err := hydraOauthConfig.Exchange(oauth2.NoContext, code)
      if err != nil {
        fmt.Println(err)
        c.HTML(http.StatusUnauthorized, "unauthorized.html", gin.H{
          "error": err.Error(),
        })
        c.Abort()
        return
      }

      isTokenValid = token.Valid()
      if isTokenValid == true {
        // Maybe we need to find a way to let the idpfe app store the access token for use. (must be stored securely client side) - should it be in a session or a secure cookie?
        //c.Header("Authorization", "Bearer " + token.AccessToken)

        // Lookup who authenticated and store

        c.Set("access_token", token.AccessToken)
        //c.Set("identity", )
        c.Next() // Grant access
        return;
      }
	  }

    // Deny by default - by requiring authentication
    redirectUrl := config.IdpFe.PublicUrl + c.Request.URL.String()
    var state = "youreallyneedtochangethis" // FIXME: This need to be calculated correctly. Maybe use CSRF token already present or new one?
    var url = config.Hydra.PublicAuthenticateUrl + "?client_id=idp-fe&scope=openid&response_type=code&state="+state+"&redirect_uri=" + redirectUrl
    c.Redirect(302, url)
    c.Abort()
  }
}

func getProfileHandler(c *gin.Context) {

  token, accessTokenExists := c.Get("access_token")
  if accessTokenExists != true {
    c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing access token"})
    c.Abort()
    return
  }

  var accessToken string = token.(string)

  identityResponse, err := idpbe.FetchIdentityFromAccessToken(config.Hydra.UserInfoUrl, accessToken)
  if err != nil {
    c.JSON(400, gin.H{"error": err.Error()})
    c.Abort()
    return
  }

  var id string = identityResponse.Sub

  // Use token to call idp-be as idp-fe on behalf of the user to fetch profile information.
  request := interfaces.IdentityRequest{
    Id: id,
  }
  profileResponse, err := idpbe.FetchProfileForIdentity(config.IdpBe.IdentitiesUrl, accessToken, request)
  if err != nil {
    c.JSON(400, gin.H{"error": err.Error()})
    c.Abort()
    return
  }

  fmt.Println(profileResponse)

  c.HTML(200, "me.html", gin.H{
    "user": profileResponse.Id,
    "email": profileResponse.Email,
  })
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
      var state = "youreallyneedtochangethis" // FIXME: This need to be calculated correctly.
      var url = config.Hydra.PublicAuthenticateUrl + "?client_id=idp-fe&scope=openid&response_type=code&state="+state+"&redirect_uri=" + config.IdpFe.DefaultRedirectUrl
      c.Redirect(302, url)
      c.Abort()
      return
    }

    var authenticateRequest = interfaces.AuthenticateRequest{
      Challenge: loginChallenge,
    }
    authenticateResponse, err := idpbe.Authenticate(config.IdpBe.AuthenticateUrl, authenticateRequest)
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

  var logoutRequest = interfaces.LogoutRequest{
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
    var authenticateRequest = interfaces.AuthenticateRequest{
      Id: form.Identity,
      Password: form.Password,
      Challenge: form.Challenge,
    }
    authenticateResponse, err := idpbe.Authenticate(config.IdpBe.AuthenticateUrl, authenticateRequest)
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
