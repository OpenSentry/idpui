package invites

import (
  "net/url"
  "net/http"
  "time"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
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

    invitesRequest := &idp.InviteReadRequest{
      Id: "009e44d3-9553-4a40-b443-509cc0d88c94",
    }
    invite, err := idp.ReadInvites(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.invites"), invitesRequest)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    t := time.Unix(invite.IssuedAt, 0)
    exp := time.Unix(invite.ExpiresAt, 0)
    f := "2006-01-02 15:04:05"

    u, err := url.Parse(config.GetString("idpui.public.url") + config.GetString("idpui.public.endpoints.invites.accept"))
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }
    q := u.Query()
    q.Add("id", invite.Id)
    u.RawQuery = q.Encode()

    invites := []InviteTemplate{
      InviteTemplate{Url: u.String(), Id:invite.Id, Email:identity.Email, InvitedBy:identity.Name, IssuedAt:t.Format(f), Expires:exp.Format(f)},
    }

    c.HTML(http.StatusOK, "invites.html", gin.H{
      "title": "Invites",
      "links": []map[string]string{
        {"href": "/public/css/dashboard.css"},
      },
      "id": identity.Id,
      "user": identity.Subject,
      "name": identity.Name,
      "invites": invites,
    })
  }
  return gin.HandlerFunc(fn)
}