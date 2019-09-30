package profiles

import (
  "net/http"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"
  "github.com/gin-contrib/sessions"
  idp "github.com/charmixer/idp/client"

  "github.com/charmixer/idpui/app"
  "github.com/charmixer/idpui/config"
  "github.com/charmixer/idpui/environment"
)

type logoutForm struct {
  Challenge string `form:"challenge" binding:"required"`
}

func ShowLogout(env *environment.State) gin.HandlerFunc {
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

    c.HTML(http.StatusOK, "logout.html", gin.H{
      "links": []map[string]string{
        {"href": "/public/css/credentials.css"},
      },
      "title": "Logout",
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "provider": "Identity Provider",
      "provideraction": "Logout of the system",
      "challenge": logoutChallenge,
      "logoutUrl": config.GetString("idpui.public.endpoints.logout"),
    })
  }
  return gin.HandlerFunc(fn)
}


func SubmitLogout(env *environment.State) gin.HandlerFunc {
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

    idpClient := app.IdpClientUsingClientCredentials(env, c)

    logoutRequest := []idp.CreateHumansLogoutRequest{ {Challenge: form.Challenge} }
    _, logouts, err := idp.LogoutHumans(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.logout"), logoutRequest)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    if logouts == nil {
      log.Debug("Logout failed. Hint: Failed to execute CreateHumansLogoutRequest")
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    status, obj, _ := idp.UnmarshalResponse(0, logouts)
    if status == 200 && obj != nil {

      logout := obj.(idp.HumanRedirect)

      session := sessions.Default(c)
      session.Clear()
      err = session.Save()
      if err != nil {
        log.Debug(err.Error())
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }

      log.WithFields(logrus.Fields{"redirect_to": logout.RedirectTo}).Debug("Redirecting")
      c.Redirect(http.StatusFound, logout.RedirectTo)
      c.Abort()
    }

    // Deny by default
    log.Debug("Unmarshal response failed")
    c.AbortWithStatus(http.StatusInternalServerError)
  }
  return gin.HandlerFunc(fn)
}

func ShowLogoutSession(env *environment.State) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowLogoutSession",
    })

    c.HTML(200, "session-logout.html", gin.H{
      "links": []map[string]string{
        {"href": "/public/css/credentials.css"},
      },
      "title": "Session",
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "provider": "Identity Provider",
      "provideraction": "Reset login session",
      "sessionLogoutUrl": config.GetString("idpui.public.endpoints.session.logout"),
    })
  }
  return gin.HandlerFunc(fn)
}

func SubmitLogoutSession(env *environment.State) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "SubmitLogoutSession",
    })

    session := sessions.Default(c)
    session.Clear()
    err := session.Save()
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }
    log.WithFields(logrus.Fields{"redirect_to": "/"}).Debug("Redirecting")
    c.Redirect(http.StatusFound, "/")
    c.Abort()
  }
  return gin.HandlerFunc(fn)
}
