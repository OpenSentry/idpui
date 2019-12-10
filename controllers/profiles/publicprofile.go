package profiles

import (
  "net/http"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  idp "github.com/opensentry/idp/client"

  "github.com/opensentry/idpui/app"
  "github.com/opensentry/idpui/config"

  bulky "github.com/charmixer/bulky/client"
)

type PublicProfileRequest struct {
  Id string `form:"id" binding:"required" validate:"required,uri"`
}

func ShowPublicProfile(env *app.Environment) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(env.Constants.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowPublicProfile",
    })

    var request PublicProfileRequest
    err := c.Bind(&request)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusBadRequest)
      return
    }

    idpClient := app.IdpClientUsingClientCredentials(env, c)

    // Look up profile information for user.
    humanRequests := []idp.ReadHumansRequest{ {Id: request.Id } }
    status, responses, err := idp.ReadHumans(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.humans.collection"), humanRequests)
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
      log.Debug("Request not OK")
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    if len(responses) > 0 {

      var resp idp.ReadHumansResponse
      status, _ := bulky.Unmarshal(0, responses, &resp)
      if status == http.StatusOK {

        human := resp[0]

        log.WithFields(logrus.Fields{"fixme": 1}).Debug("Missing implementation of public data model")

        c.HTML(http.StatusOK, "publicprofile.html", gin.H{
          "title": "Public Profile",
          "links": []map[string]string{
            {"href": "/public/css/credentials.css"},
          },
          "provider": "Identity Provider",
          "provideraction": "Public profile",
          "id": human.Id,
          "email": "", // identity.Email,
        })
        return
      }
    }

    // Deny by default.
    log.WithFields(logrus.Fields{ "id":request.Id }).Debug("Not Found")
    c.AbortWithStatus(http.StatusNotFound)
    return
  }
  return gin.HandlerFunc(fn)
}
