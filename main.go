package main

import (
    "github.com/gin-gonic/gin"
)

type authenticationForm struct {
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


func main() {
    r := gin.Default()

    r.Static("/public", "public")

    r.LoadHTMLGlob("views/*")

    r.GET("/", getAuthenticationHandler)
    r.GET("/authenticate", getAuthenticationHandler)
    r.POST("/authenticate", postAuthenticationHandler)

    r.GET("/register", getRegisterHandler)
    r.POST("/register", postRegistrationHandler)

    r.GET("/recover", getRecoverHandler)
    r.POST("/recover", postRecoverHandler)

    r.Run() // defaults to :8080, uses env PORT if set
}

func getAuthenticationHandler(c *gin.Context) {
    c.HTML(200, "authenticate.html", nil)
}

func getRegisterHandler(c *gin.Context) {
    c.HTML(200, "register.html", nil)
}

func getRecoverHandler(c *gin.Context) {
    c.HTML(200, "recover.html", nil)
}

func postAuthenticationHandler(c *gin.Context) {
    var form authenticationForm
    c.Bind(&form)
    c.JSON(200, gin.H{
        "id": form.Identity,
        "password" : form.Password })
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
