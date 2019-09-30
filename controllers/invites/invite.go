package invites

import (
  "net/http"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"
  //"github.com/gin-contrib/sessions"
  idp "github.com/charmixer/idp/client"

  "github.com/charmixer/idpui/app"
  "github.com/charmixer/idpui/config"
  "github.com/charmixer/idpui/environment"
  "github.com/charmixer/idpui/utils"
)

type inviteForm struct {
  Email string `form:"email" binding:"required"`
  Username string `form:"username"`
  GrantedScopes []string `form:"granted_scopes[]"`
  FollowIdentities []string `form:"follow_identities[]"`
}


func ShowInvite(env *environment.State) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowInvite",
    })

    identity := app.RequireIdentity(c)
    if identity == nil {
      log.Debug("Missing Identity")
      c.AbortWithStatus(http.StatusForbidden)
      return
    }

    c.HTML(http.StatusOK, "invite.html", gin.H{
      "title": "Invite",
      "links": []map[string]string{
        {"href": "/public/css/dashboard.css"},
      },
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "name": identity.Name,
    })
  }
  return gin.HandlerFunc(fn)
}

func SubmitInvite(env *environment.State) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "SubmitInvite",
    })

    var form inviteForm
    err := c.Bind(&form)
    if err != nil {
      c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    idpClient := app.IdpClientUsingAuthorizationCode(env, c)

    inviteRequest := []idp.CreateInvitesRequest{{
      Email: form.Email,
      HintUsername: form.Username,      
    }}
    _, invite, err := idp.CreateInvites(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.invite"), inviteRequest)
    if err != nil {
      log.WithFields(logrus.Fields{ "email":form.Email, "username":form.Username }).Debug("Invite failed")
      c.HTML(http.StatusInternalServerError, "invite.html", gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    log.Debug(invite)

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
