package challenges

import (
  "net/http"
  "net/url"
  "strings"
  "reflect"
  "gopkg.in/go-playground/validator.v9"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"
  "github.com/gin-contrib/sessions"
  idp "github.com/charmixer/idp/client"

  "github.com/charmixer/idpui/app"
  "github.com/charmixer/idpui/config"
  "github.com/charmixer/idpui/utils"
  "github.com/charmixer/idpui/validators"

  bulky "github.com/charmixer/bulky/client"
)

type recoverConfirmForm struct {
  Challenge        string `form:"challenge"        binding:"required" validate:"required,notblank"`
  Code             string `form:"code"             binding:"required" validate:"required,notblank"`
  Password         string `form:"password"         binding:"required" validate:"required,notblank"`
  PasswordRetyped  string `form:"password_retyped" binding:"required" validate:"required,notblank"`
}

func ShowRecoverConfirm(env *app.Environment) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(env.Constants.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowRecoverConfirm",
    })

    recoverChallenge := c.Query(RECOVER_CHALLENGE_KEY)
    if recoverChallenge == "" {
      log.WithFields(logrus.Fields{ RECOVER_CHALLENGE_KEY: recoverChallenge }).Debug("Missing " + RECOVER_CHALLENGE_KEY)
      c.AbortWithStatus(http.StatusNotFound)
      return
    }

    q := url.Values{}
    q.Add(RECOVER_CHALLENGE_KEY, recoverChallenge)

    submitUrl, err := utils.FetchSubmitUrlFromRequest(c.Request, &q)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    session := sessions.DefaultMany(c, env.Constants.SessionStoreKey)

    errors := session.Flashes(RECOVERCONFIRM_ERRORS)
    err = session.Save() // Remove flashes read, and save submit fields
    if err != nil {
      log.Debug(err.Error())
    }

    var errorCode string
    var errorPassword string
    var errorPasswordRetyped string

    if len(errors) > 0 {
      errorsMap := errors[0].(map[string][]string)
      for k, v := range errorsMap {

        if k == "code" && len(v) > 0 {
          errorCode = strings.Join(v, ", ")
        }
        if k == "password" && len(v) > 0 {
          errorPassword = strings.Join(v, ", ")
        }
        if k == "password_retyped" && len(v) > 0 {
          errorPasswordRetyped = strings.Join(v, ", ")
        }

      }
    }

    c.HTML(200, "recoverconfirm.html", gin.H{
      "title": "Recover Confirmation",
      "links": []map[string]string{
        {"href": "/public/css/credentials.css"},
      },
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "provider": "Identity Provider",
      "provideraction": "Recover your profile",
      "challenge": recoverChallenge,
      "errorCode": errorCode,
      "errorPassword": errorPassword,
      "errorPasswordRetyped": errorPasswordRetyped,
      "submitUrl": submitUrl,
    })
  }
  return gin.HandlerFunc(fn)
}

func SubmitRecoverConfirm(env *app.Environment) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(env.Constants.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "SubmitRecoverConfirm",
    })

    var form recoverConfirmForm
    err := c.Bind(&form)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      return
    }

    q := url.Values{}
    q.Add(RECOVER_CHALLENGE_KEY, form.Challenge)

    submitUrl, err := utils.FetchSubmitUrlFromRequest(c.Request, &q)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    session := sessions.DefaultMany(c, env.Constants.SessionStoreKey)

    errors := make(map[string][]string)
    validate := validator.New()
    validate.RegisterValidation("notblank", validators.NotBlank)
    err = validate.Struct(form)
    if err != nil {

      // Validation syntax is invalid
      if err,ok := err.(*validator.InvalidValidationError); ok{
        log.Debug(err.Error())
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }

      reflected := reflect.ValueOf(form) // Use reflector to reverse engineer struct
      for _, err := range err.(validator.ValidationErrors){

        // Attempt to find field by name and get json tag name
        field,_ := reflected.Type().FieldByName(err.StructField())
        var name string

        // If form tag doesn't exist, use lower case of name
        if name = field.Tag.Get("form"); name == ""{
          name = strings.ToLower(err.StructField())
        }

        switch err.Tag() {
        case "required":
            errors[name] = append(errors[name], "Required")
            break
        case "eqfield":
            errors[name] = append(errors[name], "Field should be equal to the "+err.Param())
            break
        case "notblank":
            errors[name] = append(errors[name], "Not Blank")
          break
        default:
            errors[name] = append(errors[name], "Invalid")
            break
        }
      }

    }

    if len(errors) > 0 {
      session.AddFlash(errors, RECOVERCONFIRM_ERRORS)
      err = session.Save()
      if err != nil {
        log.Debug(err.Error())
      }

      log.WithFields(logrus.Fields{"redirect_to": submitUrl}).Debug("Redirecting")
      c.Redirect(http.StatusFound, submitUrl)
      c.Abort()
      return
    }

    idpClient := app.IdpClientUsingClientCredentials(env, c)

    status, responses, err := idp.VerifyChallenges(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.challenges.verify"), []idp.UpdateChallengesVerifyRequest{ {OtpChallenge: form.Challenge, Code: form.Code} })
    if err != nil {
      log.WithFields( logrus.Fields{ RECOVER_CHALLENGE_KEY: form.Challenge }).Debug(err.Error()) // Security Warning: Do not log the code is like logging a password!
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    if status == http.StatusForbidden {
      c.AbortWithStatus(http.StatusForbidden)
      return
    }

    if status != http.StatusOK {
      log.WithFields(logrus.Fields{ "status":status }).Debug("Verify challenge failed")
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    if responses == nil {
      // Not found
      c.AbortWithStatus(http.StatusNotFound)
      return
    }

    var challengeVerification idp.UpdateChallengesVerifyResponse
    reqStatus, reqErrors := bulky.Unmarshal(0, responses, &challengeVerification)

    if reqStatus == http.StatusForbidden {
      c.AbortWithStatus(http.StatusForbidden)
      return
    }

    if reqStatus != http.StatusOK {

      errors := []string{}
      if len(reqErrors) > 0 {
        for _,e := range reqErrors {
          errors = append(errors, e.Error)
        }
      }

      log.WithFields(logrus.Fields{ "status":reqStatus, "errors":strings.Join(errors, ", ") }).Debug("Unmarshal UpdateChallengesVerifyResponse failed")
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    if challengeVerification.Verified == true {

      // FIXME: Call recover endpoint and redirect to success redirect.
      // FIXME: Maybe this should use an access token instead of client credentials.

      recoverRequests := []idp.UpdateHumansRecoverVerifyRequest{ {RecoverChallenge: challengeVerification.OtpChallenge, NewPassword: form.Password} }
      status, responses, err := idp.RecoverHumansVerify(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.humans.recoververification"), recoverRequests)
      if err != nil {
        log.Debug(err.Error())
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }

      if status == http.StatusForbidden {
        c.AbortWithStatus(http.StatusForbidden)
        return
      }

      if status != http.StatusOK {
        log.WithFields(logrus.Fields{ "status":status }).Debug("Recover human verify failed")
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }

      var verification idp.UpdateHumansRecoverVerifyResponse
      reqStatus, reqErrors := bulky.Unmarshal(0, responses, &verification)

      if reqStatus == http.StatusForbidden {
        c.AbortWithStatus(http.StatusForbidden)
        return
      }

      if reqStatus != http.StatusOK {

        errors := []string{}
        if len(reqErrors) > 0 {
          for _,e := range reqErrors {
            errors = append(errors, e.Error)
          }
        }

        log.WithFields(logrus.Fields{ "status":reqStatus, "errors":strings.Join(errors, ", ") }).Debug("Unmarshal UpdateHumansRecoverVerifyResponse failed")
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }

      if verification.Verified == true && verification.RedirectTo != "" {

        // Destroy user session
        session.Clear()
        err = session.Save()
        if err != nil {
          log.Debug(err.Error())
        }

        // Success, call success url redirect_to
        log.WithFields(logrus.Fields{ "redirect_to": verification.RedirectTo }).Debug("Redirecting");
        c.Redirect(http.StatusFound, verification.RedirectTo)
        c.Abort()
        return
      }

    }

    // Deny by default
    errors["code"] = append(errors["code"], "Invalid")
    session.AddFlash(errors, RECOVERCONFIRM_ERRORS)
    err = session.Save()
    if err != nil {
      log.Debug(err.Error())
    }

    log.WithFields(logrus.Fields{"redirect_to": submitUrl}).Debug("Redirecting")
    c.Redirect(http.StatusFound, submitUrl)
    c.Abort()
  }
  return gin.HandlerFunc(fn)
}