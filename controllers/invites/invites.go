package invites

import (
  "net/url"
  "net/http"
  "time"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  //"github.com/gin-contrib/sessions"
  idp "github.com/charmixer/idp/client"

  "github.com/charmixer/idpui/app"
  "github.com/charmixer/idpui/config"
  "github.com/charmixer/idpui/environment"
)

type InviteTemplate struct {
  IssuedAt string
  InvitedBy string
  Expires string
  Id string
  Email string
  Url string
}

func ShowInvites(env *environment.State) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowInvites",
    })

    identity := app.RequireIdentity(c)
    if identity == nil {
      log.Debug("Missing Identity")
      c.AbortWithStatus(http.StatusForbidden)
      return
    }

    idpClient := app.IdpClientUsingAuthorizationCode(env, c)

    status, responses, err := idp.ReadInvites(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.invites.collection"), nil)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    if status != 200 {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    f := "2006-01-02 15:04:05" // Remder time format
    var uiPendingInvites []InviteTemplate
    var uiCreatedInvites []InviteTemplate
    var uiSentInvites []InviteTemplate

    status, obj, _ := idp.UnmarshalResponse(0, responses)
    if status == 200 && obj != nil {

      invites := obj.([]idp.Invite)
      for _, invite := range invites {

        inviteAcceptUrl, err := url.Parse(config.GetString("idpui.public.url") + config.GetString("idpui.public.endpoints.invites.accept"))
        if err != nil {
          log.Debug(err.Error())
          c.AbortWithStatus(http.StatusInternalServerError)
          return
        }
        q := inviteAcceptUrl.Query()
        q.Add("id", invite.Id)
        inviteAcceptUrl.RawQuery = q.Encode()

        uiInvite := InviteTemplate{
          Url:       inviteAcceptUrl.String(),
          Id:        invite.Id,
          Email:     invite.Email,
          InvitedBy: invite.InvitedBy,
          IssuedAt:  time.Unix(invite.IssuedAt, 0).Format(f),
          Expires:   time.Unix(invite.ExpiresAt, 0).Format(f),
        }
        uiCreatedInvites = append(uiCreatedInvites, uiInvite)

      }

    }

    c.HTML(http.StatusOK, "invites.html", gin.H{
      "title": "Invites",
      "links": []map[string]string{
        {"href": "/public/css/dashboard.css"},
      },
      "id": identity.Id,
      "user": identity.Username,
      "name": identity.Name,
      "pending": uiPendingInvites,
      "created": uiCreatedInvites,
      "sent": uiSentInvites,
    })
  }
  return gin.HandlerFunc(fn)
}