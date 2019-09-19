package credentials

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
  "github.com/charmixer/idpui/utils"
)

type passwordForm struct {
  Password string `form:"password"`
  PasswordRetyped string `form:"password_retyped"`
}

func ShowPassword(env *environment.State) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowPassword",
    })

    session := sessions.Default(c)

    var idToken *oidc.IDToken
    idToken = session.Get(environment.SessionIdTokenKey).(*oidc.IDToken)
    if idToken == nil {
      c.HTML(http.StatusNotFound, "password.html", gin.H{"error": "Identity not found"})
      c.Abort()
      return
    }

    log.Debug(idToken)

    errors := session.Flashes("password.errors")
    err := session.Save() // Remove flashes read, and save submit fields
    if err != nil {
      log.Debug(err.Error())
    }

    var errorPassword string
    var errorPasswordRetyped string

    if len(errors) > 0 {
      errorsMap := errors[0].(map[string][]string)
      for k, v := range errorsMap {

        if k == "errorPassword" && len(v) > 0 {
          errorPassword = strings.Join(v, ", ")
        }

        if k == "errorPasswordRetyped" && len(v) > 0 {
          errorPasswordRetyped = strings.Join(v, ", ")
        }

      }
    }

    c.HTML(http.StatusOK, "password.html", gin.H{
      "__title": "Password",
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "id": idToken.Subject,
      "errorPassword": errorPassword,
      "errorPasswordRetyped": errorPasswordRetyped,
    })
  }
  return gin.HandlerFunc(fn)
}

func SubmitPassword(env *environment.State) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "SubmitPassword",
    })

    var form passwordForm
    err := c.Bind(&form)
    if err != nil {
      // Do better error handling in the application.
      c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    session := sessions.Default(c)

    errors := make(map[string][]string)

    password := form.Password
    if strings.TrimSpace(password) == "" {
      errors["errorPassword"] = append(errors["errorPassword"], "Missing password. Hint: Not allowed to be all whitespace")
    }

    retypedPassword := form.PasswordRetyped
    if retypedPassword != password {
      errors["errorPasswordRetyped"] = append(errors["errorPasswordRetyped"], "Must match password")
    }

    if len(errors) > 0 {
      session.AddFlash(errors, "password.errors")
      err = session.Save()
      if err != nil {
        log.Debug(err.Error())
      }

      submitUrl, err := utils.FetchSubmitUrlFromRequest(c.Request)
      if err != nil {
        log.Debug(err.Error())
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }
      log.WithFields(logrus.Fields{"redirect_to": submitUrl}).Debug("Redirecting")
      c.Redirect(http.StatusFound, submitUrl)
      c.Abort()
      return
    }

    if password == retypedPassword { // Just for safety is caught in the input error detection.

      var idToken *oidc.IDToken
      idToken = session.Get(environment.SessionIdTokenKey).(*oidc.IDToken)
      if idToken == nil {
        c.HTML(http.StatusNotFound, "password.html", gin.H{"error": "Identity not found"})
        c.Abort()
        return
      }

      log.WithFields(logrus.Fields{"fixme": 1}).Debug("Figure out if we are to use client credentials to communicate from ui to api or we wanna use the user authorized access token in ui to access api")

      var accessToken *oauth2.Token
      accessToken = session.Get(environment.SessionTokenKey).(*oauth2.Token)
      idpClient := idp.NewIdpClientWithUserAccessToken(env.HydraConfig, accessToken)

      passwordRequest := &idp.IdentitiesPasswordRequest{
        Id: idToken.Subject,
        Password: form.Password,
      }
      profile, err := idp.UpdateIdentityPassword(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.password"), passwordRequest)
      if err != nil {
        log.Debug(err.Error())
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        c.Abort()
        return
      }

      log.Debug(profile)

      log.WithFields(logrus.Fields{"fixme":1}).Debug("Redirect to where we came from")
      log.WithFields(logrus.Fields{"redirect_to": "/me"}).Debug("Redirecting")
      c.Redirect(http.StatusFound, "/me")
      c.Abort()
      return
    }

    // Deny by default. Failed to fill in the form correctly.
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
