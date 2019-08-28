package controllers

import (
  "net/http"
  "strings"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gin-contrib/sessions"
  "golang.org/x/oauth2"
  oidc "github.com/coreos/go-oidc"
  "golang-idp-fe/config"
  "golang-idp-fe/environment"
  "golang-idp-fe/gateway/idpapi"
  "golang-idp-fe/gateway/aapapi"
)

func ShowProfile(env *environment.State, route environment.Route) gin.HandlerFunc {
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
      c.HTML(http.StatusNotFound, "profile.html", gin.H{"error": "Identity not found"})
      c.Abort()
      return
    }

    var accessToken *oauth2.Token
    accessToken = session.Get(environment.SessionTokenKey).(*oauth2.Token)
    idpapiClient := idpapi.NewIdpApiClientWithUserAccessToken(env.HydraConfig, accessToken)

    // Look up profile information for user.
    request := idpapi.IdentityRequest{
      Id: idToken.Subject,
    }
    profile, err := idpapi.FetchProfile(config.GetString("idpapi.public.url") + config.GetString("idpapi.public.endpoints.identities"), idpapiClient, request)
    if err != nil {
      c.HTML(http.StatusNotFound, "profile.html", gin.H{"error": "Identity not found"})
      c.Abort()
      return
    }

    aapapiClient := aapapi.NewAapApiClient(env.AapApiConfig)

    log.Debug("Please change idpui to only have one client credential that is allowed to call idpapi and aapapi")

    var consents string = "n/a"
    consentRequest := aapapi.ConsentRequest{
      Subject: idToken.Subject,
      ClientId: env.AapApiConfig.ClientID,
      // RequestedScopes: requestedScopes, // Only look for permissions that was requested (query optimization)
    }
    grantedScopes, err := aapapi.FetchConsents(config.GetString("aapapi.public.url") + config.GetString("aapapi.public.endpoints.authorizations"), aapapiClient, consentRequest)
    if err != nil {
      log.Debug(err)
    } else {
      consents = "client_id:"+consentRequest.ClientId+ ", scopes:" + strings.Join(grantedScopes, ",")
    }

    var permissions string = "n/a"

    c.HTML(http.StatusOK, "profile.html", gin.H{
      "__title": "Profile",
      "user": idToken.Subject,
      "name": profile.Name,
      "email": profile.Email,
      "consents": consents,
      "permissions": permissions,
    })
  }
  return gin.HandlerFunc(fn)
}
