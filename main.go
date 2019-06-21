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

func init() {
  config.InitConfigurations()
}

func main() {
    r := gin.Default()

    // Use CSRF on all our forms.
    fmt.Println("Using insecure CSRF for devlopment. Do not do this in production")
    adapterCSRF := adapter.Wrap(csrf.Protect([]byte(config.IdpFe.CsrfAuthKey), csrf.Secure(false)))
    // r.Use(adapterCSRF) // Do not use this as it will make csrf tokens for public files aswell which is just extra data going over the wire, no need for that.

    r.Static("/public", "public")

    r.LoadHTMLGlob("views/*")

    r.GET("/", adapterCSRF, getAuthenticationHandler)
    r.GET("/authenticate", adapterCSRF, getAuthenticationHandler)
    r.POST("/authenticate", adapterCSRF, postAuthenticationHandler)

    r.GET("/logout", adapterCSRF, getLogoutHandler)
    r.POST("/logout", adapterCSRF, postLogoutHandler)

    r.GET("/register", adapterCSRF, getRegisterHandler)
    r.POST("/register", adapterCSRF, postRegistrationHandler)

    r.GET("/recover", adapterCSRF, getRecoverHandler)
    r.POST("/recover", adapterCSRF, postRecoverHandler)

    r.GET("/welcome", getProfileHandler)

    r.Run() // defaults to :8080, uses env PORT if set
}

func getProfileHandler(c *gin.Context) {

  // TODO Secure it using hydra.

  c.HTML(200, "profile.html", gin.H{
  })
}

func getLogoutHandler(c *gin.Context) {
  logoutChallenge := c.Query("logout_challenge")
  if logoutChallenge == "" {
    var url = config.Hydra.LogoutUrl
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
      var url = config.Hydra.AuthenticateUrl + "?client_id=idp-fe&scope=openid&response_type=code&state=youreallyneedtochangethis&redirect_uri=" + config.IdpFe.DefaultRedirectUrl
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
