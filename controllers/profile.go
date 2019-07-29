package controllers

import (
  "net/http"
  "strings"
  "fmt"

  "github.com/gin-gonic/gin"
  //"github.com/gorilla/csrf"
  "github.com/gin-contrib/sessions"
  "golang.org/x/oauth2"
  oidc "github.com/coreos/go-oidc"

  "golang-idp-fe/config"
  "golang-idp-fe/environment"
  "golang-idp-fe/gateway/idpbe"
  "golang-idp-fe/gateway/cpbe"
)

func ShowProfile(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {
    environment.DebugLog(route.LogId, "showProfile", "", c.MustGet(environment.RequestIdKey).(string))

    // NOTE: Maybe session is not a good way to do this.
    // 1. The user access /me with a browser and the access token / id token is stored in a session as we cannot make the browser redirect with Authentication: Bearer <token>
    // 2. The user is using something that supplies the access token and id token directly in the headers. (aka. no need for the session)
    var idToken *oidc.IDToken
    session := sessions.Default(c)
    idToken = session.Get(environment.SessionIdTokenKey).(*oidc.IDToken)
    if idToken == nil {
      c.HTML(http.StatusNotFound, "me.html", gin.H{"error": "Identity not found"})
      c.Abort()
      return
    }

    var accessToken *oauth2.Token
    accessToken = session.Get(environment.SessionTokenKey).(*oauth2.Token)
    idpbeClient := idpbe.NewIdpBeClientWithUserAccessToken(env.HydraConfig, accessToken)

    // Look up profile information for user.
    request := idpbe.IdentityRequest{
      Id: idToken.Subject,
    }
    profile, err := idpbe.FetchProfile(config.Discovery.IdpApi.Public.Url + config.Discovery.IdpApi.Public.Endpoints.Identities, idpbeClient, request)
    if err != nil {
      c.HTML(http.StatusNotFound, "me.html", gin.H{"error": "Identity not found"})
      c.Abort()
      return
    }


    cpbeClient := cpbe.NewCpBeClient(env.CpBeConfig)

    var consents string = "n/a"
    consentRequest := cpbe.ConsentRequest{
      Subject: idToken.Subject,
      App: "idpui", // FIXME: Formalize this. Remeber an app could have more than one identity (client_id) if we wanted to segment access within the app
      ClientId: "idpui", //authorizeResponse.ClientId, // "idpui"
      // RequestedScopes: requestedScopes, // Only look for permissions that was requested (query optimization)
    }
    grantedScopes, err := cpbe.FetchConsents(config.Discovery.AapApi.Public.Url + config.Discovery.AapApi.Public.Endpoints.Authorizations, cpbeClient, consentRequest)
    if err != nil {
      fmt.Println(err)
    } else {
      consents = "app:" + consentRequest.App + ", client_id:"+consentRequest.ClientId+ ", scopes:" + strings.Join(grantedScopes, ",")
    }

    var permissions string = "n/a"

    c.HTML(http.StatusOK, "me.html", gin.H{
      "user": idToken.Subject,
      "name": profile.Name,
      "email": profile.Email,
      "consents": consents,
      "permissions": permissions,
    })
  }
  return gin.HandlerFunc(fn)
}
