package controllers

import (
  "net/http"
  "strings"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"
  "github.com/gin-contrib/sessions"
  idp "github.com/charmixer/idp/client"

  "github.com/charmixer/idpui/config"
  "github.com/charmixer/idpui/environment"
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
      "__links": []map[string]string{
        {"href": "/public/css/main.css"},
      },
      "__title": "Recover verification",
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

    password := form.Password
    if strings.TrimSpace(password) == "" {
      errors["errorPassword"] = append(errors["errorPassword"], "Missing password. Hint: Not allowed to be all whitespace")
    }

    retypedPassword := form.PasswordRetyped
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

    idpClient := idp.NewIdpClient(env.IdpApiConfig)

    recoverRequest := &idp.IdentitiesRecoverVerificationRequest{
      Id: username,
      VerificationCode: verificationCode,
      Password: password,
      RedirectTo: "/",
    }
    recoverResponse, err := idp.RecoverIdentityVerification(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.recoververification"), recoverRequest)
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
