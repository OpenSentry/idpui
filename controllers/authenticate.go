package controllers

import (
  "net/url"
  "net/http"
  "crypto/rand"
  "encoding/base64"
  "strings"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"
  "github.com/gin-contrib/sessions"
  "idpui/config"
  "idpui/environment"
  idp "github.com/charmixer/idp/client"
)

type authenticationForm struct {
  Challenge string `form:"challenge" binding:"required"`
  Username string `form:"username" binding:"required"`
  Password string `form:"password" binding:"required"`
}

func ShowAuthentication(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowAuthentication",
    })

    loginChallenge := c.Query("login_challenge")
    if loginChallenge == "" {
      // User is visiting login page as the first part of the process, probably meaning. Want to view profile or change it.
      // IdpUi should ask hydra for a challenge to login
      initUrl, err := StartAuthenticationSession(env, c, route, log)
      if err != nil {
        log.Debug(err.Error())
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        c.Abort()
        return
      }
      log.WithFields(logrus.Fields{"redirect_to": initUrl.String()}).Debug("Redirecting")
      c.Redirect(http.StatusFound, initUrl.String())
      c.Abort()
      return
    }

    idpClient := idp.NewIdpApiClient(env.IdpApiConfig)

    var authenticateRequest = idp.AuthenticateRequest{
      Challenge: loginChallenge,
    }
    authenticateResponse, err := idp.Authenticate(config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.authenticate"), idpClient, authenticateRequest)
    if err != nil {
      log.WithFields(logrus.Fields{
        "challenge": authenticateRequest.Challenge,
      }).Debug(err.Error())
      c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    if authenticateResponse.Authenticated {
      log.WithFields(logrus.Fields{"authenticated": authenticateResponse.Authenticated, "redirect_to": authenticateResponse.RedirectTo}).Debug("Redirecting")
      c.Redirect(http.StatusFound, authenticateResponse.RedirectTo)
      c.Abort()
      return
    }

    session := sessions.Default(c)

    // Retain the values that was submittet, except passwords!
    username := session.Get("authenticate.username")

    errors := session.Flashes("authenticate.errors")
    err = session.Save() // Remove flashes read, and save submit fields
    if err != nil {
      log.Debug(err.Error())
    }

    var errorUsername string
    var errorPassword string

    if len(errors) > 0 {
      errorsMap := errors[0].(map[string][]string)
      for k, v := range errorsMap {

        if k == "errorUsername" && len(v) > 0 {
          errorUsername = strings.Join(v, ", ")
        }
        if k == "errorPassword" && len(v) > 0 {
          errorPassword = strings.Join(v, ", ")
        }

      }
    }

    c.HTML(200, "authenticate.html", gin.H{
      "__links": []map[string]string{
        {"href": "/public/css/main.css"},
      },
      "__title": "Authenticate",
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "challenge": loginChallenge,
      "username": username,
      "errorUsername": errorUsername,
      "errorPassword": errorPassword,
    })
  }
  return gin.HandlerFunc(fn)
}

func SubmitAuthentication(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "SubmitAuthentication",
    })

    var form authenticationForm
    err := c.Bind(&form)
    if err != nil {
      log.Debug(err.Error())
      c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    session := sessions.Default(c)

    // Save values if submit fails
    session.Set("authenticate.username", form.Username)
    err = session.Save()
    if err != nil {
      log.Debug(err.Error())
    }

    errors := make(map[string][]string)

    username := strings.TrimSpace(form.Username)
    if username == "" {
      errors["errorUsername"] = append(errors["errorUsername"], "Missing username")
    }

    log.WithFields(logrus.Fields{"fixme": 1}).Debug("Should we trim password?")
    password := strings.TrimSpace(form.Password)
    if password == "" {
      errors["errorPassword"] = append(errors["errorPassword"], "Missing password")
    }

    if len(errors) > 0 {
      session.AddFlash(errors, "authenticate.errors")
      err = session.Save()
      if err != nil {
        log.Debug(err.Error())
      }
      redirectTo := c.Request.URL.RequestURI() + "?login_challenge=" + form.Challenge
      log.WithFields(logrus.Fields{"redirect_to": redirectTo}).Debug("Redirecting")
      c.Redirect(http.StatusFound, redirectTo)
      c.Abort();
      return
    }

    idpClient := idp.NewIdpApiClient(env.IdpApiConfig)

    // Ask idp to authenticate the user
    var authenticateRequest = idp.AuthenticateRequest{
      Id: username,
      Password: password,
      Challenge: form.Challenge,
    }
    authenticateResponse, err := idp.Authenticate(config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.authenticate"), idpClient, authenticateRequest)
    if err != nil {
      log.WithFields(logrus.Fields{
        "id": authenticateRequest.Id,
        "challenge": authenticateRequest.Challenge,
      }).Debug(err.Error())
      c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    // User authenticated, redirect
    if authenticateResponse.Authenticated {

      // Cleanup session
      session.Delete("authenticate.username")
      session.Delete("authenticate.errors")

      err = session.Save()
      if err != nil {
        log.Debug(err.Error())
      }

      log.WithFields(logrus.Fields{
        "id": authenticateResponse.Id,
        "authenticated": authenticateResponse.Authenticated,
        "require_2fa": authenticateResponse.Require2Fa,
        "redirect_to": authenticateResponse.RedirectTo,
      }).Debug("Redirecting")
      c.Redirect(http.StatusFound, authenticateResponse.RedirectTo)
      c.Abort()
      return
    }

    // Deny by default

    if authenticateResponse.NotFound {
      errors["errorUsername"] = append(errors["errorUsername"], "Not found")
    } else {
      errors["errorUsername"] = append(errors["errorUsername"], "Invalid password")
    }
    session.AddFlash(errors, "authenticate.errors")
    err = session.Save()
    if err != nil {
      log.Debug(err.Error())
    }

    redirectTo := c.Request.URL.RequestURI() + "?login_challenge=" + form.Challenge
    log.WithFields(logrus.Fields{"redirect_to": redirectTo}).Debug("Redirecting")
    c.Redirect(http.StatusFound, redirectTo)
    c.Abort()
  }
  return gin.HandlerFunc(fn)
}

func CreateRandomStringWithNumberOfBytes(numberOfBytes int) (string, error) {
  st := make([]byte, numberOfBytes)
  _, err := rand.Read(st)
  if err != nil {
    return "", err
  }
  return base64.StdEncoding.EncodeToString(st), nil
}

func StartAuthenticationSession(env *environment.State, c *gin.Context, route environment.Route, log *logrus.Entry) (*url.URL, error) {
  var state string
  var err error

  log = log.WithFields(logrus.Fields{
    "func": "StartAuthentication",
  })

  // Always generate a new authentication session state
  session := sessions.Default(c)

  state, err = CreateRandomStringWithNumberOfBytes(64);
  if err != nil {
    log.Debug(err.Error())
    return nil, err
  }
  session.Set(environment.SessionStateKey, state)
  err = session.Save()
  if err != nil {
    log.Debug(err.Error())
    return nil, err
  }

  logSession := log.WithFields(logrus.Fields{
    "session.state.key": environment.SessionStateKey,
    "session.state.state": state,
  })
  logSession.Debug("Saved session")
  logSession.Debug("Using session")
  authUrl := env.HydraConfig.AuthCodeURL(state)
  u, err := url.Parse(authUrl)
  return u, err
}
