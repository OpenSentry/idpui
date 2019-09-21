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

  "github.com/charmixer/idpui/config"
  "github.com/charmixer/idpui/environment"
  "github.com/charmixer/idpui/utils"
  "github.com/charmixer/idpui/validators"
)

type verifyForm struct {
  Challenge string `form:"challenge" binding:"required" validate:"required,notblank"`
  Code string `form:"code" binding:"required" validate:"required,notblank"`
}

func ShowVerify(env *environment.State) gin.HandlerFunc {
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

        if k == "code" && len(v) > 0 {
          errorCode = strings.Join(v, ", ")
        }

      }
    }

    c.HTML(200, "verify.html", gin.H{
      "title": "OTP Verification",
      "links": []map[string]string{
        {"href": "/public/css/credentials.css"},
      },
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "provider": "Identity Provider",
      "provideraction": "Verify one time password",
      "challenge": otpChallenge,
      "errorCode": errorCode,
    })
  }
  return gin.HandlerFunc(fn)
}

func SubmitVerify(env *environment.State) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "SubmitVerify",
    })

    var form verifyForm
    err := c.Bind(&form)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      return
    }

    q := url.Values{}
    q.Add("otp_challenge", form.Challenge)

    session := sessions.Default(c)

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
      session.AddFlash(errors, "verify.errors")
      err = session.Save()
      if err != nil {
        log.Debug(err.Error())
      }

      submitUrl, err := utils.FetchSubmitUrlFromRequest(c.Request, &q)
      if err != nil {
        log.Debug(err.Error())
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }
      log.WithFields(logrus.Fields{"redirect_to": submitUrl}).Debug("Redirecting")
      c.Redirect(http.StatusFound, submitUrl)
      c.Abort()
      return
    }


    idpClient := idp.NewIdpClient(env.IdpApiConfig)

    verifyRequest := &idp.ChallengeVerifyRequest{
      OtpChallenge: form.Challenge,
      Code: form.Code,
    }
    verifyResponse, err := idp.VerifyChallenge(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.challenges.verify"), verifyRequest)
    if err != nil {
      log.WithFields(logrus.Fields{
        "otp_challenge": form.Challenge,
        // Do not log the code is like logging a password!
      }).Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    if verifyResponse.Verified == true {

      // Append otp_challenge to redirect_to
      u, err := url.Parse(verifyResponse.RedirectTo)
      if err != nil {
        log.WithFields(logrus.Fields{
          "otp_challenge": verifyResponse.OtpChallenge,
          "redirect_to": verifyResponse.RedirectTo,
        }).Debug(err.Error())
        c.JSON(http.StatusBadRequest, gin.H{"error": "Redirect invalid. Hint: The challenge redirect_to url is invalid"})
        c.Abort()
        return;
      }

      q := u.Query()
      q.Set("otp_challenge", verifyResponse.OtpChallenge)
      u.RawQuery = q.Encode()
      redirectTo := u.String()

      log.WithFields(logrus.Fields{"redirect_to": redirectTo}).Debug("Redirecting")
      c.Redirect(http.StatusFound, redirectTo)
      c.Abort()
      return
    }

    // Deny by default
    errors["code"] = append(errors["code"], "Invalid")
    session.AddFlash(errors, "verify.errors")
    err = session.Save()
    if err != nil {
      log.Debug(err.Error())
    }

    submitUrl, err := utils.FetchSubmitUrlFromRequest(c.Request, &q)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }
    log.WithFields(logrus.Fields{"redirect_to": submitUrl}).Debug("Redirecting")
    c.Redirect(http.StatusFound, submitUrl)
    c.Abort()
  }
  return gin.HandlerFunc(fn)
}
