package controllers

import (
  "net/url"
  "net/http"
  "crypto/hmac"
  "crypto/sha256"
  "encoding/hex"
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
    id := c.Query("id")
    sig := c.Query("sig")

    if loginChallenge == "" || id == "" || sig == "" {
      log.Debug("Missing login_challenge")
      log.WithFields(logrus.Fields{
        "login_challenge": loginChallenge,
        "id": id,
        "sig": sig,
      }).Debug("Missing login_challenge, id or sig")
      c.JSON(http.StatusNotFound, gin.H{"error": "Missing login_challenge, id or sig"})
      c.Abort()
      return
    }

    // Check none tampered with the redirect input
    redirectTo :=  "/passcode?login_challenge=" + loginChallenge + "&id=" + id

    sigKey := config.GetString("2fa.sigkey")
    h := hmac.New(sha256.New, []byte(sigKey))
    h.Write([]byte(redirectTo))
    sha := hex.EncodeToString(h.Sum(nil))

    if sha != sig {
      c.JSON(http.StatusNotFound, gin.H{"error": "Signature does not match. Hint: Did soneone tamper with the challenge or id paramters?"})
      c.Abort();
      return;
    }

    c.HTML(200, "passcode.html", gin.H{
      "__title": "Passcode",
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "challenge": loginChallenge,
      "username": id,
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

    log.WithFields(logrus.Fields{"fixme": 1}).Debug("We need to check that the post request challenge was also made from the right client and not tampered with")

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
    retryLoginUrl := "/?login_challenge=" + form.Challenge + "&id=" + passcodeRequest.Id + "&passcode_error=Passcode verification failed";
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
