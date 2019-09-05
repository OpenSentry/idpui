package controllers

import (
  "net/http"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"
  "github.com/gin-contrib/sessions"
  idp "github.com/charmixer/idpclient"

  "github.com/charmixer/idpui/config"
  "github.com/charmixer/idpui/environment"
)

type logoutForm struct {
  Challenge string `form:"challenge" binding:"required"`
}

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
      "__title": "Logout",
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

    var form logoutForm
    err := c.Bind(&form)
    if err != nil {
      // Do better error handling in the application.
      c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    idpClient := idp.NewIdpClient(env.IdpApiConfig)

    logoutRequest := &idp.IdentitiesLogoutRequest{
      Challenge: form.Challenge,
    }
    logout, err := idp.LogoutIdentity(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.logout"), logoutRequest)
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
      "__title": "Session logout",
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
