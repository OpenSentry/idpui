package invites

import (
  "net/http"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"
  idp "github.com/charmixer/idp/client"

  "github.com/charmixer/idpui/app"
  "github.com/charmixer/idpui/config"
  "github.com/charmixer/idpui/environment"
  "github.com/charmixer/idpui/utils"

  bulky "github.com/charmixer/bulky/client"
)

type sendForm struct {
  Id string `form:"id" binding:"required" validate:"required,uuid"`
}

func ShowInvitesSend(env *environment.State) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowInvitesSend",
    })

    identity := app.RequireIdentity(c)
    if identity == nil {
      log.Debug("Missing Identity")
      c.AbortWithStatus(http.StatusForbidden)
      return
    }

    inviteId := c.Query("id")
    if inviteId == "" {
      c.AbortWithStatus(http.StatusNotFound)
      return
    }

    idpClient := app.IdpClientUsingAuthorizationCode(env, c)

    inviteRequest := []idp.ReadInvitesRequest{ {Id: inviteId} }
    status, responses, err := idp.ReadInvites(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.invites.collection"), inviteRequest)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    if status == 200 {

      var resp idp.ReadInvitesResponse
      status, _ = bulky.Unmarshal(0, responses, &resp)
      if status == 200 {
        invite := resp[0]
        
        c.HTML(http.StatusOK, "invites_send.html", gin.H{
          "title": "Send Invite",
          "links": []map[string]string{
            {"href": "/public/css/dashboard.css"},
          },
          csrf.TemplateTag: csrf.TemplateField(c.Request),
          "id": invite.Id,
          "email": invite.Email,
          "user": invite.Username,
        })
        return
      }

    }

    // Deny by default
    c.AbortWithStatus(http.StatusNotFound)
  }
  return gin.HandlerFunc(fn)
}

func SubmitInvitesSend(env *environment.State) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "SubmitInvitesSend",
    })

    var form sendForm
    err := c.Bind(&form)
    if err != nil {
      c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    identity := app.RequireIdentity(c)
    if identity == nil {
      log.Debug("Missing Identity")
      c.AbortWithStatus(http.StatusForbidden)
      return
    }

    idpClient := app.IdpClientUsingAuthorizationCode(env, c)

    inviteSendRequest := []idp.CreateInvitesSendRequest{ {Id: form.Id} }
    status, responses, err := idp.CreateInvitesSend(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.invites.send"), inviteSendRequest)
    if err != nil {
      log.WithFields(logrus.Fields{ "id":form.Id }).Debug("Send invite failed")
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    if status == 200 {

      var invite idp.CreateInvitesSendResponse
      status, _ = bulky.Unmarshal(0, responses, &invite)
      if status == 200 {
        log.WithFields(logrus.Fields{"id": invite.Id}).Debug("Send invite")

        redirectTo := config.GetString("idpui.public.url") + config.GetString("idpui.public.endpoints.invites.collection")
        log.WithFields(logrus.Fields{"redirect_to": redirectTo}).Debug("Redirecting")
        c.Redirect(http.StatusFound, redirectTo)
        c.Abort()
        return
      }

    }

    // Deny by default.
    submitUrl, err := utils.FetchSubmitUrlFromRequest(c.Request, nil)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }
    log.WithFields(logrus.Fields{"redirect_to": submitUrl}).Debug("Redirecting")
    c.Redirect(http.StatusFound, submitUrl)
    c.Abort()
  }
  return gin.HandlerFunc(fn)
}