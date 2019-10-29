package credentials

import (
  "net/http"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gin-contrib/sessions"

  "github.com/charmixer/idpui/app"
)

func ShowSeeYouLater(env *app.Environment) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(env.Constants.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowSeeYouLater",
    })

    var sessionCleared bool = true

    session := sessions.Default(c)
    session.Clear()
    err := session.Save()
    if err != nil {
      log.Debug(err.Error())
      sessionCleared = false
    }

    c.HTML(http.StatusOK, "seeyoulater.html", gin.H{
      "title": "See You Later",
      "links": []map[string]string{
        {"href": "/public/css/dashboard.css"},
      },
      "sessionCleared": sessionCleared,
    })
  }
  return gin.HandlerFunc(fn)
}