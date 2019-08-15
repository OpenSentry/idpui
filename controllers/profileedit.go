package controllers

import (
  "strings"
  "net/http"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"
  "github.com/gin-contrib/sessions"
  "golang.org/x/oauth2"
  oidc "github.com/coreos/go-oidc"
  "golang-idp-fe/config"
  "golang-idp-fe/environment"
  "golang-idp-fe/gateway/idpapi"
)

type profileEditForm struct {
  Name string `form:"display-name"`
  Email string `form:"email"`
}

func ShowProfileEdit(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowProfile",
    })

    session := sessions.Default(c)

    // NOTE: Maybe session is not a good way to do this.
    // 1. The user access /me with a browser and the access token / id token is stored in a session as we cannot make the browser redirect with Authentication: Bearer <token>
    // 2. The user is using something that supplies the access token and id token directly in the headers. (aka. no need for the session)
    var idToken *oidc.IDToken
    idToken = session.Get(environment.SessionIdTokenKey).(*oidc.IDToken)
    if idToken == nil {
      c.HTML(http.StatusNotFound, "me.html", gin.H{"error": "Identity not found"})
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
      c.HTML(http.StatusNotFound, "me.html", gin.H{"error": "Identity not found"})
      c.Abort()
      return
    }

    // Retain the values that was submittet
    submittetName := session.Get("profileedit.display-name")
    submittetEmail := session.Get("profileedit.email")

    errors := session.Flashes("profileedit.errors")
    err = session.Save() // Remove flashes read, and save submit fields
    if err != nil {
      log.Debug(err.Error())
    }

    // Use submittet value from flash or default from db.
    var displayName string
    if submittetName == nil {
      displayName = profile.Name
    } else {
      displayName = submittetName.(string)
    }

    var email string
    if submittetEmail == nil {
      email = profile.Email
    } else {
      email = submittetEmail.(string)
    }

    var errorEmail string
    var errorDisplayName string

    if len(errors) > 0 {
      errorsMap := errors[0].(map[string][]string)
      for k, v := range errorsMap {

        if k == "errorEmail" && len(v) > 0 {
          errorEmail = strings.Join(v, ", ")
        }

        if k == "errorDisplayName" && len(v) > 0 {
          errorDisplayName = strings.Join(v, ", ")
        }
      }
    }

    c.HTML(http.StatusOK, "meedit.html", gin.H{
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "user": idToken.Subject,
      "displayName": displayName,
      "email": email,
      "errorEmail": errorEmail,
      "errorDisplayName": errorDisplayName,
      "registeredDisplayName": profile.Name,
      "registeredEmail": profile.Email,
    })
  }
  return gin.HandlerFunc(fn)
}

func SubmitProfileEdit(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "SubmitProfileEdit",
    })

    var form profileEditForm
    err := c.Bind(&form)
    if err != nil {
      // Do better error handling in the application.
      c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    session := sessions.Default(c)

    // NOTE: Maybe session is not a good way to do this.
    // 1. The user access /me with a browser and the access token / id token is stored in a session as we cannot make the browser redirect with Authentication: Bearer <token>
    // 2. The user is using something that supplies the access token and id token directly in the headers. (aka. no need for the session)
    var idToken *oidc.IDToken
    idToken = session.Get(environment.SessionIdTokenKey).(*oidc.IDToken)
    if idToken == nil {
      c.HTML(http.StatusNotFound, "me.html", gin.H{"error": "Identity not found"})
      c.Abort()
      return
    }

    var accessToken *oauth2.Token
    accessToken = session.Get(environment.SessionTokenKey).(*oauth2.Token)
    idpapiClient := idpapi.NewIdpApiClientWithUserAccessToken(env.HydraConfig, accessToken)

    // Save values if submit fails
    session.Set("profileedit.display-name", form.Name)
    session.Set("profileedit.email", form.Email)
    err = session.Save()
    if err != nil {
      log.Debug(err.Error())
    }

    errors := make(map[string][]string)

    if len(errors) > 0 {
      session.AddFlash(errors, "profileedit.errors")
      err = session.Save()
      if err != nil {
        log.Debug(err.Error())
      }
      log.WithFields(logrus.Fields{"redirect_to": route.URL}).Debug("Redirecting")
      c.Redirect(http.StatusFound, route.URL)
      c.Abort();
      return
    }

    var profileRequest = idpapi.Profile{
      Id: idToken.Subject,
      Email: form.Email,
      Name: form.Name,
    }
    _ /* profile */, err = idpapi.UpdateProfile(config.GetString("idpapi.public.url") + config.GetString("idpapi.public.endpoints.identities"), idpapiClient, profileRequest)
    if err != nil {
      log.Debug(err.Error())
      c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    // Cleanup session
    session.Delete("profileedit.display-name")
    session.Delete("profileedit.email")

    // Register success message
    session.AddFlash(1, "profileedit.success")

    err = session.Save()
    if err != nil {
      log.Debug(err.Error())
    }

    // Registration successful, return to create new ones, but with success message
    log.WithFields(logrus.Fields{"redirect_to": "/me/edit"}).Debug("Redirecting")
    c.Redirect(http.StatusFound, route.URL)
    return

    // Deny by default. Failed to fill in the form correctly.
    /*log.WithFields(logrus.Fields{"redirect_to": route.URL}).Debug("Redirecting")
    c.Redirect(http.StatusFound, route.URL)
    c.Abort()*/
  }
  return gin.HandlerFunc(fn)
}
