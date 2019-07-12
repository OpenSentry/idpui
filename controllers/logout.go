package controllers

import (
  "net/http"

  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"
  "github.com/gin-contrib/sessions"

  "golang-idp-fe/config"
  "golang-idp-fe/environment"
  "golang-idp-fe/gateway/idpbe"
)

func ShowLogout(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {
    environment.DebugLog(route.LogId, "showLogout", "", c.MustGet(environment.RequestIdKey).(string))
    logoutChallenge := c.Query("logout_challenge")
    if logoutChallenge == "" {
      // No logout challenge ask hydra for one.
      c.Redirect(http.StatusFound, config.Hydra.PublicLogoutUrl)
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
    environment.DebugLog(route.LogId, "submitLogout", "", c.MustGet(environment.RequestIdKey).(string))
    var form authenticationForm
    err := c.Bind(&form)
    if err != nil {
      // Do better error handling in the application.
      c.JSON(400, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    idpbeClient := idpbe.NewIdpBeClient(env.IdpBeConfig)

    var request = idpbe.LogoutRequest{
      Challenge: form.Challenge,
    }
    logout, err := idpbe.Logout(config.IdpBe.LogoutUrl, idpbeClient, request)
    if err != nil {
      c.JSON(400, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    session := sessions.Default(c)
    session.Clear()
    session.Save()

    c.Redirect(302, logout.RedirectTo)
    c.Abort()
  }
  return gin.HandlerFunc(fn)
}

func ShowLogoutSession(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {
    environment.DebugLog(route.LogId, "showLogoutSession", "", c.MustGet(environment.RequestIdKey).(string))

    c.HTML(200, "session-logout.html", gin.H{
      csrf.TemplateTag: csrf.TemplateField(c.Request),
    })
  }
  return gin.HandlerFunc(fn)
}

func SubmitLogoutSession(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {
    environment.DebugLog(route.LogId, "submitLogoutSession", "", c.MustGet(environment.RequestIdKey).(string))

    session := sessions.Default(c)
    session.Clear()
    session.Save()
    c.Redirect(302, "/me")
    c.Abort()
  }
  return gin.HandlerFunc(fn)
}
