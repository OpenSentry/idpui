package controllers

import (
  "net/url"
  "net/http"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"
  "golang-idp-fe/config"
  "golang-idp-fe/environment"
  "golang-idp-fe/gateway/idpapi"
)

type passcodeForm struct {
  Challenge string `form:"challenge" binding:"required"`
  Username string `form:"username" binding:"required"`
  Passcode string `form:"passcode" binding:"required"`
}

func ShowPasscode(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowPasscode",
    })

    loginChallenge := c.Query("login_challenge")
    if loginChallenge == "" {
      log.Debug("Missing login challenge")
      log.WithFields(logrus.Fields{
        "challenge": "",
        "redirect_to": "/authenticate",
      }).Debug("Redirecting")
      c.Redirect(http.StatusFound, "/authenticate")
      c.Abort()
      return
    }

    idpapiClient := idpapi.NewIdpApiClient(env.IdpApiConfig)

    var authenticateRequest = idpapi.AuthenticateRequest{
      Challenge: loginChallenge,
    }
    authenticateResponse, err := idpapi.Authenticate(config.GetString("idpapi.public.url") + config.GetString("idpapi.public.endpoints.authenticate"), idpapiClient, authenticateRequest)
    if err != nil {
      c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    if authenticateResponse.Authenticated == false {
      log.WithFields(logrus.Fields{
        "challenge": authenticateRequest.Challenge,
        "id": authenticateResponse.Id,
        "authenticated": authenticateResponse.Authenticated,
        "redirect_to": "/authenticate",
      }).Debug("Redirecting")
      c.Redirect(http.StatusFound, "/authenticate")
      c.Abort()
      return
    }

    if authenticateResponse.Require2Fa == false {
      log.WithFields(logrus.Fields{
        "challenge": authenticateRequest.Challenge,
        "redirect_to": authenticateResponse.RedirectTo,
      }).Debug("Redirecting")
      c.Redirect(http.StatusFound, authenticateResponse.RedirectTo)
      c.Abort()
      return
    }

    c.HTML(200, "passcode.html", gin.H{
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "challenge": authenticateRequest.Challenge,
      "username": authenticateResponse.Id,
    })
  }
  return gin.HandlerFunc(fn)
}

func SubmitPasscode(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "SubmitAuthentication",
    })

    var form passcodeForm
    err := c.Bind(&form)
    if err != nil {
      log.Debug(err.Error())
      c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    idpapiClient := idpapi.NewIdpApiClient(env.IdpApiConfig)

    log.WithFields(logrus.Fields{"fixme":1}).Debug("Do we need to call FetchIdentity here to ensure posted username is correct?")

    log.WithFields(logrus.Fields{"fixme":1}).Debug("should this use NewIdpApiClientWithUserAccessToken instead as http client?")
    var passcodeRequest = idpapi.PasscodeRequest{
      Id: form.Username,
      Passcode: form.Passcode,
      Challenge: form.Challenge,
    }
    passcodeResponse, err := idpapi.VerifyPasscode(config.GetString("idpapi.public.url") + config.GetString("idpapi.public.endpoints.passcode"), idpapiClient, passcodeRequest)
    if err != nil {
      log.WithFields(logrus.Fields{
        "id": passcodeRequest.Id,
        "challenge": passcodeRequest.Challenge,
      }).Debug(err.Error())
      c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    if passcodeResponse.Verified {
      log.WithFields(logrus.Fields{"redirect_to": passcodeResponse.RedirectTo}).Debug("Redirecting")
      c.Redirect(http.StatusFound, passcodeResponse.RedirectTo)
      c.Abort()
      return
    }

    // Deny by default
    // Reject the login challenge.
    log.WithFields(logrus.Fields{"fixme": 1}).Debug("Move error to session flash")
    retryLoginUrl := "/?login_challenge=" + form.Challenge + "&login_error=Passcode verification failed";
    retryUrl, err := url.Parse(retryLoginUrl)
    if err != nil {
      log.Debug(err.Error())
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
