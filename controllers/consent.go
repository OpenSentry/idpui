package controllers

import (
  "net/http"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"
  "github.com/gin-contrib/sessions"
  oidc "github.com/coreos/go-oidc"
  "idpui/environment"
  idp "github.com/charmixer/idp/client"
)

func ShowConsent(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowConsent",
    })

    c.HTML(http.StatusOK, "consent.html", gin.H{
      "__title": "Consent",
      csrf.TemplateTag: csrf.TemplateField(c.Request),
    })
  }
  return gin.HandlerFunc(fn)
}

func SubmitConsent(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "SubmitConsent",
    })

    var idToken *oidc.IDToken
    session := sessions.Default(c)
    idToken = session.Get(environment.SessionIdTokenKey).(*oidc.IDToken)
    if idToken == nil {
      c.HTML(http.StatusNotFound, "consent.html", gin.H{"error": "Identity not found"})
      c.Abort()
      return
    }

    idpClient := idp.NewIdpApiClient(env.IdpApiConfig)

    request := idp.RevokeConsentRequest{
      Id: idToken.Subject,
    }
    r, err := idp.RevokeConsent("fixme", idpClient, request)
    if err != nil {
      c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
      c.Abort()
      return
    }
    c.JSON(http.StatusOK, gin.H{"status": r})
  }
  return gin.HandlerFunc(fn)
}
