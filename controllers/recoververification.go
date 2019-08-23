package controllers

import (
  "net/http"
  "strings"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"
  "github.com/gin-contrib/sessions"
  "golang-idp-fe/config"
  "golang-idp-fe/environment"
  "golang-idp-fe/gateway/idpapi"
)

type verificationForm struct {
  Username         string `form:"username" binding:"required"`
  VerificationCode string `form:"verification_code" binding:"required"`
  Password         string `form:"password" binding:"required"`
  PasswordRetyped  string `form:"password_retyped" binding:"required"`
}

func ShowRecoverVerification(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowRecoverVerification",
    })

    session := sessions.Default(c)

    username := session.Get("recoververification.username")

    errors := session.Flashes("recoververification.errors")
    err := session.Save() // Remove flashes read, and save submit fields
    if err != nil {
      log.Debug(err.Error())
    }

    var errorUsername string
    var errorVerificationCode string
    var errorPassword string
    var errorPasswordRetyped string

    if len(errors) > 0 {
      errorsMap := errors[0].(map[string][]string)
      for k, v := range errorsMap {

        if k == "errorUsername" && len(v) > 0 {
          errorUsername = strings.Join(v, ", ")
        }

        if k == "errorVerificationCode" && len(v) > 0 {
          errorVerificationCode = strings.Join(v, ", ")
        }
        if k == "errorPassword" && len(v) > 0 {
          errorPassword = strings.Join(v, ", ")
        }
        if k == "errorPasswordRetyped" && len(v) > 0 {
          errorPasswordRetyped = strings.Join(v, ", ")
        }

      }
    }

    c.HTML(http.StatusOK, "recoververification.html", gin.H{
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "username": username,
      "errorUsername": errorUsername,
      "errorVerificationCode": errorVerificationCode,
      "errorPassword": errorPassword,
      "errorPasswordRetyped": errorPasswordRetyped,
    })
  }
  return gin.HandlerFunc(fn)
}

func SubmitRecoverVerification(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "SubmitRecoverVerification",
    })

    var form verificationForm
    err := c.Bind(&form)
    if err != nil {
      log.Debug(err.Error())
      c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    session := sessions.Default(c)

    errors := make(map[string][]string)

    username := strings.TrimSpace(form.Username)
    if username == "" {
      errors["errorUsername"] = append(errors["errorUsername"], "Missing username")
    }

    verificationCode := strings.TrimSpace(form.VerificationCode)
    if verificationCode == "" {
      errors["errorVerificationCode"] = append(errors["errorVerificationCode"], "Missing verification code")
    }

    log.WithFields(logrus.Fields{"fixme": 1}).Debug("Should we trim password?")
    password := strings.TrimSpace(form.Password)
    if password == "" {
      errors["errorPassword"] = append(errors["errorPassword"], "Missing password")
    }

    retypedPassword := strings.TrimSpace(form.PasswordRetyped)
    if retypedPassword == "" {
      errors["errorPasswordRetyped"] = append(errors["errorPasswordRetyped"], "Missing password")
    }

    if retypedPassword != password {
      errors["errorPasswordRetyped"] = append(errors["errorPasswordRetyped"], "Must match password")
    }

    if len(errors) > 0 {
      session.AddFlash(errors, "recoververification.errors")
      err = session.Save()
      if err != nil {
        log.Debug(err.Error())
      }
      redirectTo := route.URL
      log.WithFields(logrus.Fields{"redirect_to": redirectTo}).Debug("Redirecting")
      c.Redirect(http.StatusFound, redirectTo)
      c.Abort();
      return
    }

    idpapiClient := idpapi.NewIdpApiClient(env.IdpApiConfig)

    recoverRequest := idpapi.RecoverVerificationRequest{
      Id: username,
      VerificationCode: verificationCode,
      Password: password,
      RedirectTo: "/",
    }
    recoverResponse, err := idpapi.RecoverVerification(config.GetString("idpapi.public.url") + config.GetString("idpapi.public.endpoints.recoververification"), idpapiClient, recoverRequest)
    if err != nil {
      log.Debug(err.Error())
      c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    if recoverResponse.Verified == true && recoverResponse.RedirectTo != "" {

      // Cleanup session
      session.Delete("recoververification.username")
      session.Delete("recoververification.errors")

      // Propagete username to authenticate controller
      session.Set("authenticate.username", recoverResponse.Id)

      err = session.Save()
      if err != nil {
        log.Debug(err.Error())
      }

      log.WithFields(logrus.Fields{
        "redirect_to": recoverResponse.RedirectTo,
      }).Debug("Redirecting");
      c.Redirect(http.StatusFound, recoverResponse.RedirectTo)
      c.Abort()
      return
    }

    errors["errorVerificationCode"] = append(errors["errorVerificationCode"], "Invalid verification code")
    session.AddFlash(errors, "recoververification.errors")
    err = session.Save()
    if err != nil {
      log.Debug(err.Error())
    }

    redirectTo := route.URL
    log.WithFields(logrus.Fields{"redirect_to": redirectTo}).Debug("Redirecting")
    c.Redirect(http.StatusFound, redirectTo)
  }
  return gin.HandlerFunc(fn)
}
