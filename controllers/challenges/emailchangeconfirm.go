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
  idp "github.com/opensentry/idp/client"
  "golang.org/x/oauth2"

  "github.com/opensentry/idpui/app"
  "github.com/opensentry/idpui/config"
  "github.com/opensentry/idpui/utils"
  "github.com/opensentry/idpui/validators"

  bulky "github.com/charmixer/bulky/client"
)

type emailChangeConfirmForm struct {
  AccessToken string `form:"access_token" binding:"required" validate:"required,notblank"`
  Id          string `form:"id"           binding:"required" validate:"required,uuid"`
  Challenge   string `form:"challenge"    binding:"required" validate:"required,notblank"`
  Code        string `form:"code"         binding:"required" validate:"required,notblank"`
}

func ShowEmailChangeConfirm(env *app.Environment) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(env.Constants.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowEmailChangeConfirm",
    })

    identity := app.GetIdentity(env, c)
    if identity == nil {
      log.Debug("Missing Identity")
      c.AbortWithStatus(http.StatusForbidden)
      return
    }

    // FIXME: This gets stripped by the authorization code flow redirect which only supports the redirect uris registered for the client.
    emailChallenge := c.Query("state")
    if emailChallenge == "" {
      log.Debug("Missing email_challenge state")
      c.AbortWithStatus(http.StatusNotFound)
      return
    }

    q := url.Values{}
    q.Add(EMAIL_CHALLENGE_KEY, emailChallenge)

    submitUrl, err := utils.FetchSubmitUrlFromRequest(c.Request, &q)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    session := sessions.DefaultMany(c, env.Constants.SessionStoreKey)

    // Read challenges
    idpClient := app.IdpClientUsingClientCredentials(env, c)
    status, responses, err := idp.ReadChallenges(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.challenges.collection"), []idp.ReadChallengesRequest{ {OtpChallenge: emailChallenge} })
    if err != nil {
      log.WithFields( logrus.Fields{ EMAIL_CHALLENGE_KEY: emailChallenge }).Debug(err.Error()) // Security Warning: Do not log the code is like logging a password!
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    if status == http.StatusForbidden {
      c.AbortWithStatus(http.StatusForbidden)
      return
    }

    if status != http.StatusOK {
      log.WithFields(logrus.Fields{ "status":status }).Debug("Read challenge failed")
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    if responses == nil {
      // Not found
      c.AbortWithStatus(http.StatusNotFound)
      return
    }

    var challenges idp.ReadChallengesResponse
    reqStatus, reqErrors := bulky.Unmarshal(0, responses, &challenges)

    if reqStatus == http.StatusForbidden {
      c.AbortWithStatus(http.StatusForbidden)
      return
    }

    if reqStatus == http.StatusNotFound {
      // Challenge is probably expired
      errors := make(map[string][]string)
      errors["code"] = append(errors["code"], "Expired")
      session.AddFlash(errors, EMAILCHANGECONFIRM_ERRORS)
      err = session.Save()
      if err != nil {
        log.Debug(err.Error())
      }

      log.WithFields(logrus.Fields{"redirect_to": submitUrl}).Debug("Redirecting")
      c.Redirect(http.StatusFound, submitUrl)
      c.Abort()
      return
    }

    if reqStatus != http.StatusOK {

      errors := []string{}
      if len(reqErrors) > 0 {
        for _,e := range reqErrors {
          errors = append(errors, e.Error)
        }
      }

      log.WithFields(logrus.Fields{ "status":reqStatus, "errors":strings.Join(errors, ", ") }).Debug("Unmarshal ReadChallengesResponse failed")
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    challenge := challenges[0]

    errors := session.Flashes(EMAILCHANGECONFIRM_ERRORS)
    err = session.Save() // Remove flashes read, and save submit fields
    if err != nil {
      log.Debug(err.Error())
    }

    var errorCode string
    var errorEmail string

    if len(errors) > 0 {
      errorsMap := errors[0].(map[string][]string)
      for k, v := range errorsMap {

        if k == "code" && len(v) > 0 {
          errorCode = strings.Join(v, ", ")
        }
        if k == "email" && len(v) > 0 {
          errorEmail = strings.Join(v, ", ")
        }

      }
    }

    token := app.AccessToken(env, c)

    c.HTML(200, "emailchangeconfirm.html", gin.H{
      "title": "Email Confirmation",
      "links": []map[string]string{
        {"href": "/public/css/credentials.css"},
      },
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "provider": "Identity Provider",
      "provideraction": "Change your email",
      "access_token": token.AccessToken,
      "id": identity.Id,
      "name": identity.Name,
      "email": identity.Email,
      "newemail": challenge.Data,
      "challenge": emailChallenge,
      "errorCode": errorCode,
      "errorEmail": errorEmail,
      "submitUrl": submitUrl,
    })
  }
  return gin.HandlerFunc(fn)
}

func SubmitEmailChangeConfirm(env *app.Environment) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(env.Constants.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "SubmitEmailChangeConfirm",
    })

    var form emailChangeConfirmForm
    err := c.Bind(&form)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      return
    }

    q := url.Values{}
    q.Add(EMAIL_CHALLENGE_KEY, form.Challenge)

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
      session.AddFlash(errors, EMAILCHANGECONFIRM_ERRORS)
      err = session.Save()
      if err != nil {
        log.Debug(err.Error())
      }

      log.WithFields(logrus.Fields{"redirect_to": submitUrl}).Debug("Redirecting")
      c.Redirect(http.StatusFound, submitUrl)
      c.Abort()
      return
    }

    idpClient := app.IdpClientUsingClientCredentials(env, c) // TODO: Maybe this should be using user access token instead.
    status, responses, err := idp.VerifyChallenges(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.challenges.verify"), []idp.UpdateChallengesVerifyRequest{ {OtpChallenge: form.Challenge, Code: form.Code} })
    if err != nil {
      log.WithFields( logrus.Fields{ EMAIL_CHALLENGE_KEY: form.Challenge }).Debug(err.Error()) // Security Warning: Do not log the code is like logging a password!
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

    if reqStatus == http.StatusNotFound {
      // Challenge is probably expired
      errors["code"] = append(errors["code"], "Expired")
      session.AddFlash(errors, EMAILCHANGECONFIRM_ERRORS)
      err = session.Save()
      if err != nil {
        log.Debug(err.Error())
      }

      log.WithFields(logrus.Fields{"redirect_to": submitUrl}).Debug("Redirecting")
      c.Redirect(http.StatusFound, submitUrl)
      c.Abort()
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


      // Read challenges
      idpClient := app.IdpClientUsingClientCredentials(env, c)
      status, responses, err := idp.ReadChallenges(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.challenges.collection"), []idp.ReadChallengesRequest{ {OtpChallenge: form.Challenge} })
      if err != nil {
        log.WithFields( logrus.Fields{ EMAIL_CHALLENGE_KEY: form.Challenge }).Debug(err.Error()) // Security Warning: Do not log the code is like logging a password!
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }

      if status == http.StatusForbidden {
        c.AbortWithStatus(http.StatusForbidden)
        return
      }

      if status != http.StatusOK {
        log.WithFields(logrus.Fields{ "status":status }).Debug("Read challenge failed")
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }

      if responses == nil {
        // Not found
        c.AbortWithStatus(http.StatusNotFound)
        return
      }

      var challenges idp.ReadChallengesResponse
      reqStatus, reqErrors := bulky.Unmarshal(0, responses, &challenges)

      if reqStatus == http.StatusForbidden {
        c.AbortWithStatus(http.StatusForbidden)
        return
      }

      if reqStatus == http.StatusNotFound {
        // Challenge is probably expired
        errors := make(map[string][]string)
        errors["code"] = append(errors["code"], "Expired")
        session.AddFlash(errors, EMAILCHANGECONFIRM_ERRORS)
        err = session.Save()
        if err != nil {
          log.Debug(err.Error())
        }

        log.WithFields(logrus.Fields{"redirect_to": submitUrl}).Debug("Redirecting")
        c.Redirect(http.StatusFound, submitUrl)
        c.Abort()
        return
      }

      if reqStatus != http.StatusOK {

        errors := []string{}
        if len(reqErrors) > 0 {
          for _,e := range reqErrors {
            errors = append(errors, e.Error)
          }
        }

        log.WithFields(logrus.Fields{ "status":reqStatus, "errors":strings.Join(errors, ", ") }).Debug("Unmarshal ReadChallengesResponse failed")
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }

      challenge := challenges[0]


      oauth2Config := app.FetchOAuth2Config(env, c)
      if oauth2Config == nil {
        log.Debug("Context missing oauth2 config")
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }
      idpClientUser := idp.NewIdpClientWithUserAccessToken(oauth2Config, &oauth2.Token{
        AccessToken: form.AccessToken,
      })
      recoverRequests := []idp.UpdateHumansEmailConfirmRequest{ {EmailChallenge: challengeVerification.OtpChallenge, Email: challenge.Data} } // FIXME: Need a way to save data in a challenge that can be used by the confirmation endpoint to execeute.
      status, responses, err = idp.UpdateHumansEmailConfirm(idpClientUser, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.humans.emailchange"), recoverRequests)
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
        log.WithFields(logrus.Fields{ "status":status }).Debug("Email change failed")
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }

      var verification idp.UpdateHumansEmailConfirmResponse
      reqStatus, reqErrors = bulky.Unmarshal(0, responses, &verification)

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

        log.WithFields(logrus.Fields{ "status":reqStatus, "errors":strings.Join(errors, ", ") }).Debug("Unmarshal UpdateHumansEmailConfirmResponse failed")
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
    session.AddFlash(errors, EMAILCHANGECONFIRM_ERRORS)
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