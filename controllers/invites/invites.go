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

    invites, err := idp.ReadInvites(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.invites"), nil)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    f := "2006-01-02 15:04:05" // Remder time format
    var uiInvites []InviteTemplate
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
        Email:     identity.Email,
        InvitedBy: identity.Name,
        IssuedAt:  time.Unix(invite.IssuedAt, 0).Format(f),
        Expires:   time.Unix(invite.ExpiresAt, 0).Format(f),
      }
      uiInvites = append(uiInvites, uiInvite)
    }

    c.HTML(http.StatusOK, "invites.html", gin.H{
      "title": "Invites",
      "links": []map[string]string{
        {"href": "/public/css/dashboard.css"},
      },
      "id": identity.Id,
      "user": identity.Username,
      "name": identity.Name,
      "invites": uiInvites,
    })
  }
  return gin.HandlerFunc(fn)
}