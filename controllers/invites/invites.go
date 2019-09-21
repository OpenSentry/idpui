package invites

import (
  "net/http"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gin-contrib/sessions"
  "golang.org/x/oauth2"
  oidc "github.com/coreos/go-oidc"
  idp "github.com/charmixer/idp/client"

  "github.com/charmixer/idpui/config"
  "github.com/charmixer/idpui/environment"
)

func ShowInvites(env *environment.State) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowProfile",
    })

    // NOTE: Maybe session is not a good way to do this.
    // 1. The user access /me with a browser and the access token / id token is stored in a session as we cannot make the browser redirect with Authentication: Bearer <token>
    // 2. The user is using something that supplies the access token and id token directly in the headers. (aka. no need for the session)
    var idToken *oidc.IDToken
    session := sessions.Default(c)
    idToken = session.Get(environment.SessionIdTokenKey).(*oidc.IDToken)
    if idToken == nil {
      c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Missing id_token in session"})
      return
    }

    var accessToken *oauth2.Token
    accessToken = session.Get(environment.SessionTokenKey).(*oauth2.Token)
    idpClient := idp.NewIdpClientWithUserAccessToken(env.HydraConfig, accessToken)

    // Look up profile information for user.
    identityRequest := &idp.IdentitiesReadRequest{
      Id: idToken.Subject,
    }
    identity, err := idp.ReadIdentity(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.identities"), identityRequest)
    if err != nil {
      c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "Identity not found"})
      return
    }

    c.HTML(http.StatusOK, "invites.html", gin.H{
      "title": "Invites",
      "links": []map[string]string{
        {"href": "/public/css/dashboard.css"},
      },
      "id": idToken.Subject,
      "user": identity.Subject,
      "name": identity.Name,
    })
  }
  return gin.HandlerFunc(fn)
}