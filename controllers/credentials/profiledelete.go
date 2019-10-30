package credentials

import (
  "strings"
  "net/http"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"
  "github.com/gin-contrib/sessions"
  idp "github.com/charmixer/idp/client"

  "github.com/charmixer/idpui/app"
  "github.com/charmixer/idpui/config"
  "github.com/charmixer/idpui/utils"

  bulky "github.com/charmixer/bulky/client"
)

type profileDeleteForm struct {
  RiskAccepted string `form:"risk_accepted"`
}

func ShowProfileDelete(env *app.Environment) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(env.Constants.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowProfileDelete",
    })

    identity := app.GetIdentity(env, c)
    if identity == nil {
      log.Debug("Missing Identity")
      c.AbortWithStatus(http.StatusForbidden)
      return
    }

    session := sessions.DefaultMany(c, env.Constants.SessionStoreKey)

    riskAccepted := session.Flashes("profiledelete.risk_accepted")

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
      "title": "Delete profile",
      "links": []map[string]string{
        {"href": "/public/css/dashboard.css"},
      },
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "username": identity.Username,
      "name": identity.Name,
      "RiskAccepted": riskAccepted,
      "errorRiskAccepted": errorRiskAccepted,
      "profileDeleteUrl": "/me/delete",
    })
  }
  return gin.HandlerFunc(fn)
}

func SubmitProfileDelete(env *app.Environment) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(env.Constants.LogKey).(*logrus.Entry)
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

    identity := app.GetIdentity(env, c)
    if identity == nil {
      log.Debug("Missing Identity")
      c.AbortWithStatus(http.StatusForbidden)
      return
    }

    session := sessions.DefaultMany(c, env.Constants.SessionStoreKey)
    errors := make(map[string][]string)

    riskAccepted := len(form.RiskAccepted) > 0

    if riskAccepted == false {
      errors["errorRiskAccepted"] = append(errors["errorRiskAccepted"], "You have not accepted the risk")
    }

    if len(errors) <= 0  {
      if riskAccepted == true {

        idpClient := app.IdpClientUsingAuthorizationCode(env, c)

        deleteRequest := []idp.DeleteHumansRequest{ {Id: identity.Id} }
        _, responses, err := idp.DeleteHumans(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.humans.collection"), deleteRequest)
        if err != nil {
          log.Debug(err.Error())
          c.AbortWithStatus(http.StatusInternalServerError)
          return
        }

        if responses == nil {
          log.Debug("Delete failed. Hint: Failed to execute DeleteHumansRequest")
          c.AbortWithStatus(http.StatusInternalServerError)
          return
        }

        var resp idp.DeleteHumansResponse
        status, _ := bulky.Unmarshal(0, responses, &resp)
        if status == 200 {

          delete := resp

          // Cleanup session
          session.Delete("profiledelete.risk_accepted")
          session.Delete("profiledelete.errors")
          err = session.Save()
          if err != nil {
            log.Debug(err.Error())
          }

          redirectTo := delete.RedirectTo
          log.WithFields(logrus.Fields{"redirect_to": redirectTo}).Debug("Redirecting");
          c.Redirect(http.StatusFound, redirectTo)
          c.Abort()
          return
        }

      }
    }

    // Deny by default
    session.AddFlash(form.RiskAccepted, "profiledelete.risk_accepted")
    session.AddFlash(errors, "profiledelete.errors")
    err = session.Save()
    if err != nil {
      log.Debug(err.Error())
    }

    submitUrl, err := utils.FetchSubmitUrlFromRequest(c.Request, nil)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }
    log.WithFields(logrus.Fields{"redirect_to": submitUrl}).Debug("Redirecting")
    c.Redirect(http.StatusFound, submitUrl)
    c.Abort()
    return

  }
  return gin.HandlerFunc(fn)
}
