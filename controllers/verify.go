package controllers

import (
  "net/http"
  "strings"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"
  "github.com/gin-contrib/sessions"
  idp "github.com/charmixer/idpclient"

  "github.com/charmixer/idpui/config"
  "github.com/charmixer/idpui/environment"
)

type verifyForm struct {
  Challenge string `form:"challenge" binding:"required"`
  Code string `form:"code" binding:"required"`
}

func ShowVerify(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowVerify",
    })

    otpChallenge := c.Query("otp_challenge")
    if otpChallenge == "" {
      log.WithFields(logrus.Fields{
        "otp_challenge": otpChallenge,
      }).Debug("Missing otp_challenge")
      c.JSON(http.StatusNotFound, gin.H{"error": "Missing otp_challenge"})
      c.Abort()
      return
    }

    /*challenge, err := idp.FetchChallenge(otpChallenge)
    if err != nil {
      log.Debug(err.Error())
      log.WithFields(logrus.Fields{
        "otp_challenge": otpChallenge,
      }).Debug("OTP challenge not found")
      c.JSON(http.StatusNotFound, gin.H{"error": "OTP challenge not found"})
      c.Abort()
      return
    }*/

    session := sessions.Default(c)

    errors := session.Flashes("verify.errors")
    err := session.Save() // Remove flashes read, and save submit fields
    if err != nil {
      log.Debug(err.Error())
    }

    var errorCode string

    if len(errors) > 0 {
      errorsMap := errors[0].(map[string][]string)
      for k, v := range errorsMap {

        if k == "errorCode" && len(v) > 0 {
          errorCode = strings.Join(v, ", ")
        }

      }
    }

    c.HTML(200, "verify.html", gin.H{
      "__title": "OTP verification",
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "challenge": otpChallenge,
      "errorCode": errorCode,
    })
  }
  return gin.HandlerFunc(fn)
}

func SubmitVerify(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "SubmitVerify",
    })

    var form verifyForm
    err := c.Bind(&form)
    if err != nil {
      log.Debug(err.Error())
      c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    session := sessions.Default(c)
    errors := make(map[string][]string)

    idpClient := idp.NewIdpClient(env.IdpApiConfig)

    verifyRequest := &idp.ChallengeVerifyRequest{
      OtpChallenge: form.Challenge,
      Code: form.Code,
    }
    verifyResponse, err := idp.VerifyChallenge(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.otp"), verifyRequest)
    if err != nil {
      log.Debug(err.Error())
      log.WithFields(logrus.Fields{
        "otp_challenge": form.Challenge,
        // Do not log the code is like logging a password!
      }).Debug("Failed to verify otp_challenge")
      c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify otp_challenge"})
      c.Abort()
      return
    }

    if verifyResponse.Verified {
      log.WithFields(logrus.Fields{"redirect_to": verifyResponse.RedirectTo}).Debug("Redirecting")
      c.Redirect(http.StatusFound, verifyResponse.RedirectTo)
      c.Abort()
      return
    }

    // Deny by default
    //if verifyResponse.NotFound {
    //  errors["errorCode"] = append(errors["errorCode"], "Not found")
    //} else {
      errors["errorCode"] = append(errors["errorCode"], "Invalid code")
    //}
    session.AddFlash(errors, "verify.errors")
    err = session.Save()
    if err != nil {
      log.Debug(err.Error())
    }

    redirectTo := c.Request.URL.RequestURI() + "?otp_challenge=" + form.Challenge
    log.WithFields(logrus.Fields{"redirect_to": redirectTo}).Debug("Redirecting")
    c.Redirect(http.StatusFound, redirectTo)
    c.Abort()
  }
  return gin.HandlerFunc(fn)
}
