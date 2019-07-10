package controllers

import (
  "net/http"

  "github.com/gin-gonic/gin"
  //"github.com/gorilla/csrf"
  "github.com/gin-contrib/sessions"
  oidc "github.com/coreos/go-oidc"

  "golang-idp-fe/config"
  "golang-idp-fe/environment"
  "golang-idp-fe/gateway/idpbe"
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

    idpbeClient := idpbe.NewIdpBeClient(env.IdpBeConfig)

    // Look up profile information for user.
    request := idpbe.IdentityRequest{
      Id: idToken.Subject,
    }
    profile, err := idpbe.FetchProfile(config.IdpBe.IdentitiesUrl, idpbeClient, request)
    if err != nil {
      c.HTML(http.StatusNotFound, "me.html", gin.H{"error": "Identity not found"})
      c.Abort()
      return
    }

    c.HTML(http.StatusOK, "me.html", gin.H{
      "user": idToken.Subject,
      "name": profile.Name,
      "email": profile.Email,
    })
  }
  return gin.HandlerFunc(fn)
}
