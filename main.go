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

    r.GET("/register", adapterCSRF, getRegisterHandler)
    r.POST("/register", adapterCSRF, postRegistrationHandler)

    r.GET("/recover", adapterCSRF, getRecoverHandler)
    r.POST("/recover",adapterCSRF, postRecoverHandler)

    r.Run() // defaults to :8080, uses env PORT if set
}

func getAuthenticationHandler(c *gin.Context) {
    loginChallenge := c.Query("login_challenge")
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

func postAuthenticationHandler(c *gin.Context) {
    var form authenticationForm
    err := c.Bind(&form)

    if err != nil {
      // Do better error handling in the application.
      c.JSON(400, gin.H{"error": err.Error()})
      return
    }

    // Ask idp-be to authenticate the user
    var authenticateRequest = interfaces.AuthenticateRequest{
      Id: form.Identity,
      Password: form.Password,
      Challenge: form.Challenge,
    }
    authenticateResponse, err := idpbe.Authenticate(config.IdpFe.IdpBackendUrl, authenticateRequest)
    if err != nil {
      c.JSON(400, gin.H{"error": err.Error()})
      return
    }

    // User authenticated, redirect
    if authenticateResponse.Authenticated {
      c.Redirect(302, authenticateResponse.RedirectTo)
      return
    }

    // Deny by default
    // Failed authentication, retry login challenge.
    retryLoginUrl := "/?login_challenge=" + form.Challenge + "&login_error=Authentication Failure";
    retryUrl, err := url.Parse(retryLoginUrl)
    if err != nil {
      c.JSON(400, gin.H{"error": err.Error()})
      return
    }
    c.Redirect(302, retryUrl.String())
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
