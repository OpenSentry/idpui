package profiles

import (
  "net/http"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  idp "github.com/charmixer/idp/client"

  "github.com/charmixer/idpui/app"
  "github.com/charmixer/idpui/config"
  "github.com/charmixer/idpui/environment"

  bulky "github.com/charmixer/bulky/client"
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

    idpClient := app.IdpClientUsingClientCredentials(env, c)

    // Look up profile information for user.
    humanRequest := []idp.ReadHumansRequest{ {Id: request.Id } }
    _, responses, err := idp.ReadHumans(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.humans.collection"), humanRequest)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    if len(responses) > 0 {

      var resp idp.ReadHumansResponse
      status, _ := bulky.Unmarshal(0, responses, &resp)
      if status == 200 {

        human := resp[0]

        log.WithFields(logrus.Fields{"fixme": 1}).Debug("Implement data filtering on public data")

        c.HTML(http.StatusOK, "publicprofile.html", gin.H{
          "title": "Public Profile",
          "links": []map[string]string{
            {"href": "/public/css/dashboard.css"},
          },

          "id": human.Id,
          "user": "", //identity.Subject,
          "name": "", // identity.Name,
          "email": "", // identity.Email,
        })
      }
    }

    // Deny by default.
    log.WithFields(logrus.Fields{ "id":request.Id }).Debug("Not Found")
    c.AbortWithStatus(http.StatusNotFound)
    return
  }
  return gin.HandlerFunc(fn)
}
