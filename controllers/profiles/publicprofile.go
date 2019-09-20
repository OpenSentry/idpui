package profiles

import (
  "net/http"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  idp "github.com/charmixer/idp/client"

  "github.com/charmixer/idpui/config"
  "github.com/charmixer/idpui/environment"
)

type PublicProfileRequest struct {
  Id string `form:"id" binding:"required"`
}

func ShowPublicProfile(env *environment.State) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowPublicProfile",
    })

    var request PublicProfileRequest
    err := c.Bind(&request)
    if err != nil {
      c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      return
    }

    idpClient := idp.NewIdpClient(env.IdpApiConfig)

    // Look up profile information for user.
    identityRequest := &idp.IdentitiesReadRequest{
      Id: request.Id,
    }
    identity, err := idp.ReadIdentity(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.identities"), identityRequest)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    log.WithFields(logrus.Fields{"fixme": 1}).Debug("Implement data filtering on public data")

    c.HTML(http.StatusOK, "publicprofile.html", gin.H{
      "title": "Public Profile",
      "links": []map[string]string{
        {"href": "/public/css/dashboard.css"},
      },

      "id": identity.Id,
      "user": "", //identity.Subject,
      "name": "", // identity.Name,
      "email": "", // identity.Email,
    })
  }
  return gin.HandlerFunc(fn)
}
