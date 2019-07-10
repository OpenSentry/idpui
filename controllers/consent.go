package controllers

import (
  "net/http"

  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"
  "github.com/gin-contrib/sessions"
  oidc "github.com/coreos/go-oidc"

  //"golang-idp-fe/config"
  "golang-idp-fe/environment"
  "golang-idp-fe/gateway/idpbe"
)

func ShowConsent(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {
    environment.DebugLog(route.LogId, "showConsent", "", c.MustGet(environment.RequestIdKey).(string))
    c.HTML(http.StatusOK, "consent.html", gin.H{
      csrf.TemplateTag: csrf.TemplateField(c.Request),
    })
  }
  return gin.HandlerFunc(fn)
}

func SubmitConsent(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {
    environment.DebugLog(route.LogId, "submitConsent", "", c.MustGet(environment.RequestIdKey).(string))

    var idToken *oidc.IDToken
    session := sessions.Default(c)
    idToken = session.Get(environment.SessionIdTokenKey).(*oidc.IDToken)
    if idToken == nil {
      c.HTML(http.StatusNotFound, "consent.html", gin.H{"error": "Identity not found"})
      c.Abort()
      return
    }

    idpbeClient := idpbe.NewIdpBeClient(env.IdpBeConfig)

    request := idpbe.RevokeConsentRequest{
      Id: idToken.Subject,
    }
    r, err := idpbe.RevokeConsent("fixme", idpbeClient, request)
    if err != nil {
      c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
      c.Abort()
      return
    }
    c.JSON(http.StatusOK, gin.H{"status": r})
  }
  return gin.HandlerFunc(fn)
}
