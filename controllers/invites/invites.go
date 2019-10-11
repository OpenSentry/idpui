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

  bulky "github.com/charmixer/bulky/client"
)

type InviteTemplate struct {
  IssuedAt string
  InvitedBy string
  Expires string
  Id string
  Email string
  GrantsUrl string
  SendUrl string
  SendCounter int64
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
    var uiCreatedInvites []InviteTemplate
    var uiSentInvites []InviteTemplate

    var invites idp.ReadInvitesResponse
    status, _ = bulky.Unmarshal(0, responses, &invites)
    if status == 200 {

      for _, invite := range invites {

        grantsUrl, err := url.Parse(config.GetString("aapui.public.url") + config.GetString("aapui.public.endpoints.access.grant"))
        if err != nil {
          log.Debug(err.Error())
          c.AbortWithStatus(http.StatusInternalServerError)
          return
        }
        q := grantsUrl.Query()
        q.Add("id", invite.Id)
        grantsUrl.RawQuery = q.Encode()

        sendUrl, err := url.Parse(config.GetString("idpui.public.url") + config.GetString("idpui.public.endpoints.invites.send"))
        if err != nil {
          log.Debug(err.Error())
          c.AbortWithStatus(http.StatusInternalServerError)
          return
        }
        q = sendUrl.Query()
        q.Add("id", invite.Id)
        sendUrl.RawQuery = q.Encode()

        uiInvite := InviteTemplate{
          GrantsUrl: grantsUrl.String(),
          SendUrl:   sendUrl.String(),
          Id:        invite.Id,
          Email:     invite.Email,
          InvitedBy: invite.InvitedBy,
          IssuedAt:  time.Unix(invite.IssuedAt, 0).Format(f),
          Expires:   time.Unix(invite.ExpiresAt, 0).Format(f),
          SendCounter: 0,
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
      "created": uiCreatedInvites,
      "sent": uiSentInvites,
    })
  }
  return gin.HandlerFunc(fn)
}