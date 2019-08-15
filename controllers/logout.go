package controllers

import (
  "net/http"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"
  "github.com/gin-contrib/sessions"
  "golang-idp-fe/config"
  "golang-idp-fe/environment"
  "golang-idp-fe/gateway/idpapi"
)

func ShowLogout(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowLogout",
    })

    logoutChallenge := c.Query("logout_challenge")
    if logoutChallenge == "" {
      // No logout challenge ask hydra for one.
      var redirectTo string = config.GetString("hydra.public.url") + config.GetString("hydra.public.endpoints.logout")
      log.WithFields(logrus.Fields{"redirect_to": redirectTo}).Debug("Redirecting")
      c.Redirect(http.StatusFound, redirectTo)
      c.Abort()
      return
    }

    logoutError := c.Query("logout_error")
    c.HTML(http.StatusOK, "logout.html", gin.H{
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "challenge": logoutChallenge,
      "logout_error": logoutError,
    })
  }
  return gin.HandlerFunc(fn)
}


func SubmitLogout(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "SubmitLogout",
    })

    var form authenticationForm
    err := c.Bind(&form)
    if err != nil {
      // Do better error handling in the application.
      c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    idpapiClient := idpapi.NewIdpApiClient(env.IdpApiConfig)

    var request = idpapi.LogoutRequest{
      Challenge: form.Challenge,
    }
    logout, err := idpapi.Logout(config.GetString("idpapi.public.url") + config.GetString("idpapi.public.endpoints.logout"), idpapiClient, request)
    if err != nil {
      c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    session := sessions.Default(c)
    session.Clear()
    session.Save()

    log.WithFields(logrus.Fields{"redirect_to": logout.RedirectTo}).Debug("Redirecting")
    c.Redirect(http.StatusFound, logout.RedirectTo)
    c.Abort()
  }
  return gin.HandlerFunc(fn)
}

func ShowLogoutSession(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowLogoutSession",
    })

    c.HTML(200, "session-logout.html", gin.H{
      csrf.TemplateTag: csrf.TemplateField(c.Request),
    })
  }
  return gin.HandlerFunc(fn)
}

func SubmitLogoutSession(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "SubmitLogoutSession",
    })

    session := sessions.Default(c)
    session.Clear()
    session.Save()
    log.WithFields(logrus.Fields{"redirect_to": "/me"}).Debug("Redirecting")
    c.Redirect(http.StatusFound, "/me")
    c.Abort()
  }
  return gin.HandlerFunc(fn)
}
