package controllers

import (
  "net/http"

  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  //"github.com/gorilla/csrf"
  //"github.com/gin-contrib/sessions"

  //"golang-idp-fe/config"
  "golang-idp-fe/environment"
  //"golang-idp-fe/gateway/idpbe"
)

type recoverForm struct {
    Identity string `form:"identity"`
    Password string `form:"password"`
}

func ShowRecover(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "route.logid": route.LogId,
      "component": "idpui",
      "func": "ShowRecover",
    })
    log.Debug("Received recover request")

    c.HTML(http.StatusOK, "recover.html", nil)
  }
  return gin.HandlerFunc(fn)
}

func SubmitRecover(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "route.logid": route.LogId,
      "component": "idpui",
      "func": "SubmitRecover",
    })
    log.Debug("Received recover request")

    var form recoverForm
    c.Bind(&form)
    c.JSON(http.StatusOK, gin.H{"id": form.Identity })
  }
  return gin.HandlerFunc(fn)
}
