package profiles

import (
  "net/http"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"
  "github.com/gin-contrib/sessions"
  "golang.org/x/oauth2"
  oidc "github.com/coreos/go-oidc"
  idp "github.com/charmixer/idp/client"

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

    // NOTE: Maybe session is not a good way to do this.
    // 1. The user access /me with a browser and the access token / id token is stored in a session as we cannot make the browser redirect with Authentication: Bearer <token>
    // 2. The user is using something that supplies the access token and id token directly in the headers. (aka. no need for the session)
    var idToken *oidc.IDToken
    session := sessions.Default(c)
    idToken = session.Get(environment.SessionIdTokenKey).(*oidc.IDToken)
    if idToken == nil {
      c.HTML(http.StatusNotFound, "invite.html", gin.H{"error": "Identity not found"})
      c.Abort()
      return
    }

    var accessToken *oauth2.Token
    accessToken = session.Get(environment.SessionTokenKey).(*oauth2.Token)
    idpClient := idp.NewIdpClientWithUserAccessToken(env.HydraConfig, accessToken)

    // Sanity check. Access token id must exist.
    identityRequest := &idp.IdentitiesReadRequest{
      Id: idToken.Subject,
    }
    identity, err := idp.ReadIdentity(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.identities"), identityRequest)
    if err != nil {
      c.HTML(http.StatusNotFound, "invite.html", gin.H{"error": "Identity not found"})
      c.Abort()
      return
    }

    log.WithFields(logrus.Fields{"fixme": 1}).Debug("Find all permission identity is allowed to grant (maygrant?)")

    s := []string{"read:identity", "openid"}
    f := []string{identity.Id}

    var mayGrantScopes = make(map[int]map[string]string)
    for index, name := range s {
      mayGrantScopes[index] = map[string]string{
        "name": name,
      }
    }

    var followIdentities = make(map[int]map[string]string)
    for index, name := range f {
      followIdentities[index] = map[string]string{
        "name": name,
      }
    }

    c.HTML(http.StatusOK, "invite.html", gin.H{
      /*"links": []map[string]string{
        {"href": "/public/css/dashboard.css"},
      },*/
      "__links": []map[string]string{
        {"href": "/public/css/main.css"},
      },
      "__title": "Invite",
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "name": identity.Name,
      "mayGrantScopes": mayGrantScopes,
      "followIdentities": followIdentities,
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

    // NOTE: Maybe session is not a good way to do this.
    // 1. The user access /me with a browser and the access token / id token is stored in a session as we cannot make the browser redirect with Authentication: Bearer <token>
    // 2. The user is using something that supplies the access token and id token directly in the headers. (aka. no need for the session)
    var idToken *oidc.IDToken
    session := sessions.Default(c)
    idToken = session.Get(environment.SessionIdTokenKey).(*oidc.IDToken)
    if idToken == nil {
      c.HTML(http.StatusNotFound, "invite.html", gin.H{"error": "Identity not found"})
      c.Abort()
      return
    }

    var accessToken *oauth2.Token
    accessToken = session.Get(environment.SessionTokenKey).(*oauth2.Token)
    idpClient := idp.NewIdpClientWithUserAccessToken(env.HydraConfig, accessToken)

    inviteRequest := &idp.IdentitiesInviteCreateRequest{
      Id: idToken.Subject,
      Email: form.Email,
      Username: form.Username,
      GrantedScopes: form.GrantedScopes,
      PleaseFollow: []string{idToken.Subject},
      TTL: 60*60*24, // 1 hour
    }
    invite, err := idp.CreateInvite(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.invite"), inviteRequest)
    if err != nil {
      log.WithFields(logrus.Fields{"email": inviteRequest.Email, "username": inviteRequest.Username}).Debug("Failed to create invite")
      c.HTML(http.StatusInternalServerError, "invite.html", gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    log.WithFields(logrus.Fields{"id":invite.Id}).Debug("Invite created")

    submitUrl, err := utils.FetchSubmitUrlFromRequest(c.Request)
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
