package profiles

import (
  "net/http"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  //"github.com/gin-contrib/sessions"
  //"golang.org/x/oauth2"
  //oidc "github.com/coreos/go-oidc"
  idp "github.com/charmixer/idp/client"

  //"github.com/charmixer/idpui/config"
  "github.com/charmixer/idpui/environment"
)

func ShowProfile(env *environment.State) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowProfile",
    })

    identity, exists := c.Get("identity")
    if exists == true {

      identity := identity.(*idp.IdentitiesReadResponse)
      c.HTML(http.StatusOK, "profile.html", gin.H{
        "title": "Profile",
        "links": []map[string]string{
          {"href": "/public/css/dashboard.css"},
        },
        "id": identity.Id,
        "user": identity.Subject,
        "password": identity.Password,
        "name": identity.Name,
        "email": identity.Email,
        "totp_required": identity.TotpRequired,
      })
      return
    }

    log.Debug("Missing Identity in Context")
    c.AbortWithStatus(http.StatusForbidden)
    return
  }
  return gin.HandlerFunc(fn)
}
