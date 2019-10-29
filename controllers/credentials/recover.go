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

type recoverForm struct {
    Email string `form:"email" binding:"required" validate:"required,email"`
}

func ShowRecover(env *app.Environment) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(env.Constants.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowRecover",
    })

    session := sessions.Default(c)

    errors := session.Flashes("recover.errors")
    err := session.Save() // Remove flashes read, and save submit fields
    if err != nil {
      log.Debug(err.Error())
    }

    var errorEmail string

    if len(errors) > 0 {
      errorsMap := errors[0].(map[string][]string)
      for k, v := range errorsMap {
        if k == "email" && len(v) > 0 {
          errorEmail = strings.Join(v, ", ")
        }
      }
    }

    c.HTML(200, "recover.html", gin.H{
      "title": "Register",
      "links": []map[string]string{
        {"href": "/public/css/credentials.css"},
      },
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "provider": "Identity Provider",
      "provideraction": "Recover an identity registered in the system",
      "recoverUrl": config.GetString("idpui.public.endpoints.recover"),
      "loginUrl": config.GetString("idpui.public.endpoints.login"),
      "errorEmail": errorEmail,
    })
  }
  return gin.HandlerFunc(fn)
}

func SubmitRecover(env *app.Environment) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(env.Constants.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "SubmitRecover",
    })

    var form recoverForm
    err := c.Bind(&form)
    if err != nil {
      c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      return
    }

    session := sessions.Default(c)

    // Save values if submit fails
    session.Set("recover.email", form.Email)
    err = session.Save()
    if err != nil {
      log.Debug(err.Error())
    }

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

    idpClient := app.IdpClientUsingClientCredentials(env, c)

    identityRequest := []idp.ReadHumansRequest{ {Email: form.Email} }
    _, humans, err := idp.ReadHumans(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.humans.collection"), identityRequest)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    if humans != nil {

      var resp idp.ReadHumansResponse
      status, _ := bulky.Unmarshal(0, humans, &resp)
      if status == 200 {

        human := resp[0]

        log.WithFields(logrus.Fields{ "id":human.Id, "username":human.Username, "email":human.Email }).Debug("Human found")

        recoverRequest := []idp.CreateHumansRecoverRequest{ {Id: human.Id} }
        _, recoverResponse, err := idp.RecoverHumans(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.humans.recover"), recoverRequest)
        if err != nil {
          log.Debug(err.Error())
          c.AbortWithStatus(http.StatusInternalServerError)
          return
        }

        if recoverResponse == nil {
          log.Debug("Recover failed")
          c.AbortWithStatus(http.StatusInternalServerError)
          return
        }

        var resp idp.CreateHumansRecoverResponse
        status, _ := bulky.Unmarshal(0, recoverResponse, &resp)
        if status == 200 {

          recover := resp

          // Propagate selected user to verification controller to keep urls clean
          session.Set("recoververification.id", recover.Id)

          // Cleanup session
          session.Delete("recover.email")
          session.Delete("recover.errors")

          err = session.Save()
          if err != nil {
            log.Debug(err.Error())
          }

          log.WithFields(logrus.Fields{ "redirect_to": recover.RedirectTo }).Debug("Redirecting");
          c.Redirect(http.StatusFound, recover.RedirectTo)
          c.Abort()
          return
        }

      }

    }

    errors["email"] = append(errors["email"], "Not Found")
    session.AddFlash(errors, "recover.errors")
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
  return gin.HandlerFunc(fn)
}
