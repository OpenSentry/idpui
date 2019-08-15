package controllers

import (
  "net/http"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "golang-idp-fe/environment"
)

type recoverForm struct {
    Identity string `form:"identity"`
    Password string `form:"password"`
}

func ShowRecover(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowRecover",
    })    

    c.HTML(http.StatusOK, "recover.html", nil)
  }
  return gin.HandlerFunc(fn)
}

func SubmitRecover(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "SubmitRecover",
    })
    log.Debug("Received recover request")

    var form recoverForm
    c.Bind(&form)
    c.JSON(http.StatusOK, gin.H{"id": form.Identity })
  }
  return gin.HandlerFunc(fn)
}
