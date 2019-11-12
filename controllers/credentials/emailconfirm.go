package credentials

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

type emailConfirmForm struct {
  Challenge string `form:"challenge" binding:"required" validate:"required,notblank"`
  Code string `form:"code" binding:"required" validate:"required,notblank"`
}

const EMAILCONFIRM_ERRORS = "emailconfirm.errors"
const EMAIL_CHALLENGE_KEY = "email_challenge"

func ShowEmailConfirm(env *app.Environment) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(env.Constants.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowEmailConfirm",
    })

    emailChallenge := c.Query(EMAIL_CHALLENGE_KEY)
    if emailChallenge == "" {
      log.Debug("Missing " + EMAIL_CHALLENGE_KEY)
      c.AbortWithStatus(http.StatusNotFound)
      return
    }
    log = log.WithFields(logrus.Fields{ EMAIL_CHALLENGE_KEY: emailChallenge })

    q := url.Values{}
    q.Add(EMAIL_CHALLENGE_KEY, emailChallenge)

    submitUrl, err := utils.FetchSubmitUrlFromRequest(c.Request, &q)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    session := sessions.DefaultMany(c, env.Constants.SessionStoreKey)

    errors := session.Flashes(EMAILCONFIRM_ERRORS)
    err = session.Save() // Remove flashes read, and save submit fields
    if err != nil {
      log.Debug(err.Error())
    }

    var errorCode string

    if len(errors) > 0 {
      errorsMap := errors[0].(map[string][]string)
      for k, v := range errorsMap {

        if k == "code" && len(v) > 0 {
          errorCode = strings.Join(v, ", ")
        }

      }
    }

    c.HTML(200, "emailconfirm.html", gin.H{
      "title": "Email Confirmation",
      "links": []map[string]string{
        {"href": "/public/css/credentials.css"},
      },
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "provider": "Identity Provider",
      "provideraction": "Confirm your email",
      "challenge": emailChallenge,
      "errorCode": errorCode,
      "submitUrl": submitUrl,
    })
  }
  return gin.HandlerFunc(fn)
}

func SubmitEmailConfirm(env *app.Environment) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(env.Constants.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "SubmitEmailConfirm",
    })

    var form emailConfirmForm
    err := c.Bind(&form)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      return
    }
    log = log.WithFields(logrus.Fields{ EMAIL_CHALLENGE_KEY: form.Challenge})

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
      session.AddFlash(errors, EMAILCONFIRM_ERRORS)
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

    status, responses, err := idp.VerifyChallenges(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.challenges.verify"), []idp.UpdateChallengesVerifyRequest{ {
      OtpChallenge: form.Challenge,
      Code: form.Code,
    } })
    if err != nil {
      log.Debug(err.Error()) // Security Warning: Do not log the code is like logging a password!
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }
    if responses == nil {

      // Not found

      c.AbortWithStatus(http.StatusNotFound)
      return
    }

    var challengeVerification idp.UpdateChallengesVerifyResponse
    status, restErr := bulky.Unmarshal(0, responses, &challengeVerification)
    if restErr != nil {
      for _,e := range restErr {
        errors["notification"] = append(errors["notification"], e.Error)
      }
    }

    if status == http.StatusOK {

      if challengeVerification.Verified == true {

        // Destroy user session
        session.Clear()
        err = session.Save()
        if err != nil {
          log.Debug(err.Error())
        }

        // Append email_challenge to redirect_to
        u, err := url.Parse(challengeVerification.RedirectTo)
        if err != nil {
          log.WithFields(logrus.Fields{
            EMAIL_CHALLENGE_KEY: challengeVerification.OtpChallenge,
            "redirect_to": challengeVerification.RedirectTo,
          }).Debug(err.Error())
          c.AbortWithStatus(http.StatusInternalServerError)
          return
        }

        q := u.Query()
        q.Set(EMAIL_CHALLENGE_KEY, challengeVerification.OtpChallenge)
        u.RawQuery = q.Encode()
        redirectTo := u.String()

        log.WithFields(logrus.Fields{"redirect_to": redirectTo}).Debug("Redirecting")
        c.Redirect(http.StatusFound, redirectTo)
        c.Abort()
        return
      }

    }

    // Deny by default
    errors["code"] = append(errors["code"], "Invalid")
    session.AddFlash(errors, EMAILCONFIRM_ERRORS)
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