package controllers

import (
  "net/url"
  "net/http"
  "crypto/rand"
  "encoding/base64"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"
  "github.com/gin-contrib/sessions"
  "golang-idp-fe/config"
  "golang-idp-fe/environment"
  "golang-idp-fe/gateway/idpapi"
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

    idpapiClient := idpapi.NewIdpApiClient(env.IdpApiConfig)

    var authenticateRequest = idpapi.AuthenticateRequest{      
      Challenge: loginChallenge,
    }
    authenticateResponse, err := idpapi.Authenticate(config.GetString("idpapi.public.url") + config.GetString("idpapi.public.endpoints.authenticate"), idpapiClient, authenticateRequest)
    if err != nil {
      log.WithFields(logrus.Fields{
        "challenge": authenticateRequest.Challenge,
      }).Debug(err.Error())
      c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    if authenticateResponse.Authenticated {
      log.WithFields(logrus.Fields{"redirect_to": authenticateResponse.RedirectTo}).Debug("Redirecting")
      c.Redirect(http.StatusFound, authenticateResponse.RedirectTo)
      c.Abort()
      return
    }

    loginError := c.Query("login_error")
    c.HTML(200, "authenticate.html", gin.H{
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "challenge": loginChallenge,
      "login_error": loginError,
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

    idpapiClient := idpapi.NewIdpApiClient(env.IdpApiConfig)

    // Ask idpapi to authenticate the user
    var authenticateRequest = idpapi.AuthenticateRequest{
      Id: form.Username,
      Password: form.Password,
      Challenge: form.Challenge,
    }
    authenticateResponse, err := idpapi.Authenticate(config.GetString("idpapi.public.url") + config.GetString("idpapi.public.endpoints.authenticate"), idpapiClient, authenticateRequest)
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

      // Authentication requried two factor
      if authenticateResponse.Require2Fa {
        redirectTo := "/passcode?login_challenge=" + authenticateRequest.Challenge
        log.WithFields(logrus.Fields{
          "id": authenticateResponse.Id,
          "authenticated": authenticateResponse.Authenticated,
          "require_2fa": authenticateResponse.Require2Fa,
          "redirect_to": redirectTo,
        }).Debug("Redirecting")
        c.Redirect(http.StatusFound, redirectTo)
        c.Abort()
        return
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
    // Failed authentication, retry login challenge.
    log.WithFields(logrus.Fields{"fixme": 1}).Debug("Move error to session flash")
    retryLoginUrl := "/?login_challenge=" + form.Challenge + "&login_error=Authentication Failure";
    retryUrl, err := url.Parse(retryLoginUrl)
    if err != nil {
      c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
      c.Abort()
      return
    }
    log.WithFields(logrus.Fields{"redirect_to": retryUrl.String()}).Debug("Redirecting")
    c.Redirect(http.StatusFound, retryUrl.String())
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
