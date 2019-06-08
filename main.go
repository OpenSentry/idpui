package main

import (
    "github.com/gin-gonic/gin"
)

type authenticationForm struct {
    Identity string `form:"identity"`
    Password string `form:"password"`
}

func main() {
    r := gin.Default()

    r.LoadHTMLGlob("views/*")
    r.GET("/", indexHandler)
    r.POST("/authenticate", authenticationHandler)

    r.Run(":8080")
}

func indexHandler(c *gin.Context) {
    c.HTML(200, "authentication.html", nil)
}

func authenticationHandler(c *gin.Context) {
    var form authenticationForm
    c.Bind(&form)
    c.JSON(200, gin.H{"id": form.Identity, "password" : form.Password})
}
