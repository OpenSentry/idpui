package credentials

import (
  "net/http"
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

type profileDeleteVerificationForm struct {
  VerificationCode string `form:"verification_code" binding:"required" validate:"required,notblank"`
}

func ShowProfileDeleteVerification(env *app.Environment) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(env.Constants.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowProfileDeleteVerification",
    })

    identity := app.GetIdentity(env, c)
    if identity == nil {
      log.Debug("Missing Identity")
      c.AbortWithStatus(http.StatusForbidden)
      return
    }

    session := sessions.Default(c)

    errors := session.Flashes("profiledeleteverification.errors")
    err := session.Save() // Remove flashes read, and save submit fields
    if err != nil {
      log.Debug(err.Error())
    }

    var errorVerificationCode string

    if len(errors) > 0 {
      errorsMap := errors[0].(map[string][]string)
      for k, v := range errorsMap {

        if k == "verification_code" && len(v) > 0 {
          errorVerificationCode = strings.Join(v, ", ")
        }

      }
    }

    c.HTML(http.StatusOK, "profiledeleteverification.html", gin.H{
      "title": "Delete Profile",
      "links": []map[string]string{
        {"href": "/public/css/credentials.css"},
      },
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "provider": "Identity Provider",
      "provideraction": "Verify deletion of your profile",
      "id": identity.Id,
      "errorVerificationCode": errorVerificationCode,
    })
  }
  return gin.HandlerFunc(fn)
}

func SubmitProfileDeleteVerification(env *app.Environment) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(env.Constants.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "SubmitProfileDeleteVerification",
    })

    var form profileDeleteVerificationForm
    err := c.Bind(&form)
    if err != nil {
      log.Debug(err.Error())
      c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    identity := app.GetIdentity(env, c)
    if identity == nil {
      log.Debug("Missing Identity")
      c.AbortWithStatus(http.StatusForbidden)
      return
    }

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
      session.AddFlash(errors, "recoververification.errors")
      err = session.Save()
      if err != nil {
        log.Debug(err.Error())
      }

      submitUrl, err := utils.FetchSubmitUrlFromRequest(c.Request, nil)
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

    idpClient := app.IdpClientUsingAuthorizationCode(env, c)

    deleteRequest := []idp.UpdateHumansDeleteVerifyRequest{{
      Id: identity.Id,
      Code: form.VerificationCode,
      RedirectTo: config.GetString("idpui.public.url") + config.GetString("idp.public.endpoints.profile"),
    }}
    _, deleteResponse, err := idp.DeleteHumansVerify(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.humans.deleteverification"), deleteRequest)
    if err != nil {
      log.Debug(err.Error())
      c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    if deleteResponse != nil {

      var resp idp.UpdateHumansDeleteVerifyResponse
      status, _ := bulky.Unmarshal(0, deleteResponse, &resp)
      if status == 200 {

        verification := resp

        if verification.Verified == true && verification.RedirectTo != "" {

          // Destroy user session
          session.Clear()
          err = session.Save()
          if err != nil {
            log.Debug(err.Error())
          }

          log.WithFields(logrus.Fields{ "redirect_to": verification.RedirectTo }).Debug("Redirecting");
          c.Redirect(http.StatusFound, verification.RedirectTo)
          c.Abort()
          return
        }

      }

    }

    errors["verification_code"] = append(errors["verification_code"], "Invalid")
    session.AddFlash(errors, "profiledeleteverification.errors")
    err = session.Save()
    if err != nil {
      log.Debug(err.Error())
    }

    submitUrl, err := utils.FetchSubmitUrlFromRequest(c.Request, nil)
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
