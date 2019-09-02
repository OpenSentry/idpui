package controllers

import (
  "strings"
  "net/http"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"
  "github.com/gin-contrib/sessions"
  "golang.org/x/oauth2"
  oidc "github.com/coreos/go-oidc"
  "idpui/config"
  "idpui/environment"
  "idpui/gateway/idp"
)

type profileDeleteForm struct {
  RiskAccepted string `form:"risk_accepted"`
}

func ShowProfileDelete(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowProfileDelete",
    })

    session := sessions.Default(c)

    // NOTE: Maybe session is not a good way to do this.
    // 1. The user access /me with a browser and the access token / id token is stored in a session as we cannot make the browser redirect with Authentication: Bearer <token>
    // 2. The user is using something that supplies the access token and id token directly in the headers. (aka. no need for the session)
    var idToken *oidc.IDToken
    idToken = session.Get(environment.SessionIdTokenKey).(*oidc.IDToken)
    if idToken == nil {
      c.HTML(http.StatusNotFound, "profiledelete.html", gin.H{"error": "Identity not found"})
      c.Abort()
      return
    }

    riskAccepted := session.Get("profiledelete.risk_accepted")

    errors := session.Flashes("profiledelete.errors")
    err := session.Save() // Remove flashes read, and save submit fields
    if err != nil {
      log.Debug(err.Error())
    }

    var errorRiskAccepted string

    if len(errors) > 0 {
      errorsMap := errors[0].(map[string][]string)
      for k, v := range errorsMap {

        if k == "errorRiskAccepted" && len(v) > 0 {
          errorRiskAccepted = strings.Join(v, ", ")
        }

      }
    }

    c.HTML(http.StatusOK, "profiledelete.html", gin.H{
      "__title": "Delete profile",
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "username": idToken.Subject,
      "RiskAccepted": riskAccepted,
      "errorRiskAccepted": errorRiskAccepted,
    })
  }
  return gin.HandlerFunc(fn)
}

func SubmitProfileDelete(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "SubmitProfileDelete",
    })

    var form profileDeleteForm
    err := c.Bind(&form)
    if err != nil {
      c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    session := sessions.Default(c)

    errors := make(map[string][]string)

    riskAccepted := len(form.RiskAccepted) > 0

    if riskAccepted == false {
      errors["errorRiskAccepted"] = append(errors["errorRiskAccepted"], "You have not accepted the risk")
    }

    if len(errors) <= 0  {
      if riskAccepted == true {

        // NOTE: Maybe session is not a good way to do this.
        // 1. The user access /me with a browser and the access token / id token is stored in a session as we cannot make the browser redirect with Authentication: Bearer <token>
        // 2. The user is using something that supplies the access token and id token directly in the headers. (aka. no need for the session)
        var idToken *oidc.IDToken
        idToken = session.Get(environment.SessionIdTokenKey).(*oidc.IDToken)
        if idToken == nil {
          c.HTML(http.StatusNotFound, "profile.html", gin.H{"error": "Identity not found"})
          c.Abort()
          return
        }

        var accessToken *oauth2.Token
        accessToken = session.Get(environment.SessionTokenKey).(*oauth2.Token)
        idpClient := idp.NewIdpApiClientWithUserAccessToken(env.HydraConfig, accessToken)

        var deleteRequest = idp.DeleteProfileRequest{
          Id: idToken.Subject,
        }
        deleteChallenge, err := idp.DeleteProfile(config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.identities"), idpClient, deleteRequest)
        if err != nil {
          log.Debug(err.Error())
          c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
          c.Abort()
          return
        }

        // Cleanup session
        session.Delete("profiledelete.risk_accepted")
        session.Delete("profiledelete.errors")
        err = session.Save()
        if err != nil {
          log.Debug(err.Error())
        }

        redirectTo := deleteChallenge.RedirectTo
        log.WithFields(logrus.Fields{"redirect_to": redirectTo}).Debug("Redirecting");
        c.Redirect(http.StatusFound, redirectTo)
        c.Abort()
        return
      }
    }

    // Deny by default
    session.Set("profiledelete.risk_accepted", form.RiskAccepted)
    session.AddFlash(errors, "profiledelete.errors")
    err = session.Save()
    if err != nil {
      log.Debug(err.Error())
    }
    log.WithFields(logrus.Fields{"redirect_to": route.URL}).Debug("Redirecting")
    c.Redirect(http.StatusFound, route.URL)
    c.Abort();
    return

  }
  return gin.HandlerFunc(fn)
}
