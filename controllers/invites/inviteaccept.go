package invites

import (
  //"net/url"
  "net/http"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  //"github.com/gorilla/csrf"
  //"github.com/gin-contrib/sessions"
  idp "github.com/charmixer/idp/client"

  "github.com/charmixer/idpui/app"
  "github.com/charmixer/idpui/config"
  "github.com/charmixer/idpui/environment"
  "github.com/charmixer/idpui/utils"
)

type inviteAcceptForm struct {
  Id string `form:"id" binding:"required"`
}

func ShowInviteAccept(env *environment.State) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowInviteAccept",
    })
/*
    inviteId := c.Query("id")
    if inviteId == "" {
      c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Missing invite id"})
      return
    }


    invitesAcceptUrl, err := url.Parse(config.GetString("idpui.public.url") + config.GetString("idpui.public.endpoints.invites.accept"))
    if err != nil {
      log.WithFields(logrus.Fields{"id": inviteId}).Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }
    q := invitesAcceptUrl.Query()
    q.Add("id", inviteId)
    invitesAcceptUrl.RawQuery = q.Encode()

    c.HTML(http.StatusOK, "inviteaccept.html", gin.H{
      "title": "Invite",
      "links": []map[string]string{
        {"href": "/public/css/dashboard.css"},
      },
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "invitesAcceptUrl": invitesAcceptUrl.String(),
      "id": inviteId,
      "ibi": "asdasd",
    })

    inviteRequest := &idp.InviteReadRequest{
      Id: inviteId,
    }

    identity := app.RequireIdentity(c)
    if identity != nil {

      idpClient := app.IdpClientUsingAuthorizationCode(env, c)

      invite, err := idp.ReadInvites(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.invites"), inviteRequest)
      if err != nil {
        log.WithFields(logrus.Fields{"id": inviteRequest.Id}).Debug(err.Error())
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }

      invitesAcceptUrl, err := url.Parse(config.GetString("idpui.public.url") + config.GetString("idpui.public.endpoints.invites.accept"))
      if err != nil {
        log.WithFields(logrus.Fields{"id": inviteId}).Debug(err.Error())
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }
      q := invitesAcceptUrl.Query()
      q.Add("id", inviteId)
      invitesAcceptUrl.RawQuery = q.Encode()

      c.HTML(http.StatusOK, "inviteaccept.html", gin.H{
        "title": "Invite",
        "links": []map[string]string{
          {"href": "/public/css/dashboard.css"},
        },
        csrf.TemplateTag: csrf.TemplateField(c.Request),
        "invitesAcceptUrl": invitesAcceptUrl.String(),
        "id": invite.Id,
      })
    }

    // Peak @ Invite to decide if register + login required or just login
    idpClient := app.IdpClientUsingClientCredentials(env, c)

    invite, err := idp.ReadInvites(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.invites"), inviteRequest)
    if err != nil {
      log.WithFields(logrus.Fields{"id": inviteRequest.Id}).Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    log.Debug(invite)
*/
    redirectTo := "/"
    log.WithFields(logrus.Fields{"redirect_to": redirectTo}).Debug("Redirecting")
    c.Redirect(http.StatusFound, redirectTo)
    c.Abort()
  }
  return gin.HandlerFunc(fn)
}

func SubmitInviteAccept(env *environment.State) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "SubmitInviteAccept",
    })

    var form inviteAcceptForm
    err := c.Bind(&form)
    if err != nil {
      log.Debug(err.Error())
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

    inviteRequest := &idp.IdentitiesInviteUpdateRequest{
      Id: form.Id,
    }
    _ /*invite*/, err = idp.UpdateInvite(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.invite"), inviteRequest)
    if err != nil {
      log.WithFields(logrus.Fields{"id": inviteRequest.Id}).Debug(err.Error())
      c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "Invite not found"})
      return
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
  }
  return gin.HandlerFunc(fn)
}
