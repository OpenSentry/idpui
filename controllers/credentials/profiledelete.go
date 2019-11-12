package credentials

import (
  "strings"
  "net/http"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"
  "github.com/gin-contrib/sessions"
  "golang.org/x/oauth2"

  idp "github.com/charmixer/idp/client"

  "github.com/charmixer/idpui/app"
  "github.com/charmixer/idpui/config"
  "github.com/charmixer/idpui/utils"

  bulky "github.com/charmixer/bulky/client"
)

type profileDeleteForm struct {
  AccessToken string `form:"access_token" binding:"required" validate:"required,notblank"`
  Id string `form:"id" binding:"required" validate:"required,uuid"`
  RedirectTo string `form:"redirect_to" binding:"required" validate:"required,uri"`
  RiskAccepted string `form:"risk_accepted"`
}

const PROFILEDELETE_ERRORS = "profiledelete.errors"

func ShowProfileDelete(env *app.Environment) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(env.Constants.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowProfileDelete",
    })

    redirectTo := c.Request.Referer() // FIXME: This does not work, when force to login the refrer will be login uri. This should be a param in the /totp?redirect_uri=... param and should be forced to only be allowed to be specified redirect uris for the client.
    if redirectTo == "" {
      redirectTo = config.GetString("meui.public.url") + config.GetString("meui.public.endpoints.profile") // FIXME should be a config default.
    }

    identity := app.GetIdentity(env, c)
    if identity == nil {
      log.Debug("Missing Identity")
      c.AbortWithStatus(http.StatusForbidden)
      return
    }

    session := sessions.DefaultMany(c, env.Constants.SessionStoreKey)

    riskAccepted := session.Flashes("profiledelete.risk_accepted")

    errors := session.Flashes(PROFILEDELETE_ERRORS)
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

    token := app.AccessToken(env, c)

    c.HTML(http.StatusOK, "profiledelete.html", gin.H{
      "title": "Delete Profile",
      "links": []map[string]string{
        {"href": "/public/css/credentials.css"},
      },
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "provider": "Identity Provider",
      "provideraction": "Delete your profile",
      "access_token": token.AccessToken,
      "redirect_to": redirectTo,
      "id": identity.Id,
      "name": identity.Name,
      "email": identity.Email,
      "profileDeleteUrl": config.GetString("idpui.public.url") + config.GetString("idpui.public.endpoints.delete"),
      "RiskAccepted": riskAccepted,
      "errorRiskAccepted": errorRiskAccepted,
    })
  }
  return gin.HandlerFunc(fn)
}

func SubmitProfileDelete(env *app.Environment, oauth2Config *oauth2.Config) gin.HandlerFunc {
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

    // Fetch the url that the submit happen to, so we can redirect back to it.
    submitUrl, err := utils.FetchSubmitUrlFromRequest(c.Request, nil)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    session := sessions.DefaultMany(c, env.Constants.SessionStoreKey)
    errors := make(map[string][]string)

    riskAccepted := len(form.RiskAccepted) > 0

    if riskAccepted == false {
      errors["errorRiskAccepted"] = append(errors["errorRiskAccepted"], "You have not accepted the risk")
    }

    if len(errors) <= 0 && riskAccepted == true {

      // Cleanup session state for controller.
      // session.Delete("profiledelete.risk_accepted")
      // session.Delete(PROFILEDELETE_ERRORS)
      session.Clear()
      err := session.Save() // Remove flashes read, and save submit fields
      if err != nil {
        log.Debug(err.Error())
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }

      idpClient := idp.NewIdpClientWithUserAccessToken(oauth2Config, &oauth2.Token{
        AccessToken: form.AccessToken,
      })
      deleteRequests := []idp.DeleteHumansRequest{ {Id:form.Id, RedirectTo:config.GetString("idpui.public.url") + config.GetString("idpui.public.endpoints.seeyoulater")} }
      status, responses, err := idp.DeleteHumans(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.humans.collection"), deleteRequests)
      if err != nil {
        log.Debug(err.Error())
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }

      if status == http.StatusForbidden {
        c.AbortWithStatus(http.StatusForbidden)
        return
      }

      if status != http.StatusOK {
        log.WithFields(logrus.Fields{ "status":status }).Debug("Delete human failed")
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }

      var resp idp.DeleteHumansResponse
      reqStatus, reqErrors := bulky.Unmarshal(0, responses, &resp)

      if reqStatus == http.StatusForbidden {
        c.AbortWithStatus(http.StatusForbidden)
        return
      }

      if reqStatus != http.StatusOK {

        errors := []string{}
        if len(reqErrors) > 0 {
          for _,e := range reqErrors {
            errors = append(errors, e.Error)
          }
        }

        log.WithFields(logrus.Fields{ "status":reqStatus, "errors":strings.Join(errors, ", ") }).Debug("Unmarshal DeleteHumansResponse failed")
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }

      // Success
      log.WithFields(logrus.Fields{"redirect_to": resp.RedirectTo}).Debug("Redirecting")
      c.Redirect(http.StatusFound, resp.RedirectTo)
      c.Abort()
      return
    }

    // Deny by default
    session.AddFlash(form.RiskAccepted, "profiledelete.risk_accepted")
    session.AddFlash(errors, PROFILEDELETE_ERRORS)
    err = session.Save()
    if err != nil {
      log.Debug(err.Error())
    }

    log.WithFields(logrus.Fields{"redirect_to": submitUrl}).Debug("Redirecting")
    c.Redirect(http.StatusFound, submitUrl)
    c.Abort()
    return

  }
  return gin.HandlerFunc(fn)
}
