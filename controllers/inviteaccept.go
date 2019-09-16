package controllers

import (
  "net/http"
  "strings"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"
  "github.com/gin-contrib/sessions"
  "golang.org/x/oauth2"
  oidc "github.com/coreos/go-oidc"
  idp "github.com/charmixer/idp/client"

  "github.com/charmixer/idpui/config"
  "github.com/charmixer/idpui/environment"
)

type inviteAcceptForm struct {
  Id string `form:"id" binding:"required"`
}

func ShowInviteAccept(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowInviteAccept",
    })

    inviteId := c.Query("invite")
    if inviteId == "" {
      log.Debug("Missing invite id")
      c.HTML(http.StatusNotFound, "inviteaccept.html", gin.H{"error": "Invite not found"})
      c.Abort()
      return
    }

    session := sessions.Default(c)

    var idToken *oidc.IDToken = session.Get(environment.SessionIdTokenKey).(*oidc.IDToken)
    if idToken == nil {
      c.HTML(http.StatusNotFound, "inviteaccept.html", gin.H{"error": "Identity not found"})
      c.Abort()
      return
    }

    var accessToken *oauth2.Token
    accessToken = session.Get(environment.SessionTokenKey).(*oauth2.Token)
    idpClient := idp.NewIdpClientWithUserAccessToken(env.HydraConfig, accessToken)

    inviteRequest := &idp.IdentitiesInviteReadRequest{
      Id: inviteId,
    }
    invite, err := idp.ReadInvite(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.invite"), inviteRequest)
    if err != nil {
      log.WithFields(logrus.Fields{"id": inviteRequest.Id}).Debug(err.Error())
      c.HTML(http.StatusNotFound, "inviteaccept.html", gin.H{"error": "Invite not found"})
      c.Abort()
      return
    }

    scopes := strings.Split(invite.GrantedScopes, " ")

    var grantScopes = make(map[int]map[string]string)
    for index, scope := range scopes {
      grantScopes[index] = map[string]string{
        "name": scope,
      }
    }

    identities := strings.Split(invite.FollowIdentities, " ")

    var followIdentities = make(map[int]map[string]string)
    for index, id := range identities {
      followIdentities[index] = map[string]string{
        "name": id,
      }
    }

    c.HTML(http.StatusOK, "inviteaccept.html", gin.H{
      "__links": []map[string]string{
        {"href": "/public/css/main.css"},
      },
      "__title": "Invite accept",
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "grantedScopes": grantScopes,
      "followIdentities": followIdentities,
      "inviteId": invite.Id,
    })
  }
  return gin.HandlerFunc(fn)
}

func SubmitInviteAccept(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "SubmitInviteAccept",
    })

    var form inviteAcceptForm
    err := c.Bind(&form)
    if err != nil {
      log.Debug(err.Error())
      c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    session := sessions.Default(c)

    var idToken *oidc.IDToken = session.Get(environment.SessionIdTokenKey).(*oidc.IDToken)
    if idToken == nil {
      c.HTML(http.StatusNotFound, "inviteaccept.html", gin.H{"error": "Identity not found"})
      c.Abort()
      return
    }

    var accessToken *oauth2.Token
    accessToken = session.Get(environment.SessionTokenKey).(*oauth2.Token)
    idpClient := idp.NewIdpClientWithUserAccessToken(env.HydraConfig, accessToken)

    inviteRequest := &idp.IdentitiesInviteUpdateRequest{
      Id: form.Id,
    }
    invite, err := idp.UpdateInvite(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.invite"), inviteRequest)
    if err != nil {
      log.WithFields(logrus.Fields{"id": inviteRequest.Id}).Debug(err.Error())
      c.HTML(http.StatusNotFound, "inviteaccept.html", gin.H{"error": "Invite not found"})
      c.Abort()
      return
    }

    redirectTo := route.URL
    log.WithFields(logrus.Fields{"id": invite.Id, "redirect_to": redirectTo}).Debug("Redirecting")
    c.Redirect(http.StatusFound, redirectTo)
  }
  return gin.HandlerFunc(fn)
}
