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
  Email      string `form:"email"       binding:"required" validate:"required,email"`
  RedirectTo string `form:"redirect_to" binding:"required" validate:"required,uri"`
}

func ShowRecover(env *app.Environment) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(env.Constants.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowRecover",
    })

    redirectTo := c.Request.Referer() // FIXME: This does not work, when force to login the refrer will be login uri. This should be a param in the /recover?redirect_uri=... param and should be forced to only be allowed to be specified redirect uris for the client.
    if redirectTo == "" {
      redirectTo = config.GetString("meui.public.url") + config.GetString("meui.public.endpoints.profile") // FIXME should be a config default.
    }

    session := sessions.DefaultMany(c, env.Constants.SessionStoreKey)

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
      "redirect_to": redirectTo,
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

    // Fetch the url that the submit happen to, so we can redirect back to it.
    submitUrl, err := utils.FetchSubmitUrlFromRequest(c.Request, nil)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    session := sessions.DefaultMany(c, env.Constants.SessionStoreKey)

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

    identityRequests := []idp.ReadHumansRequest{ {Email: form.Email} }
    status, responses, err := idp.ReadHumans(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.humans.collection"), identityRequests)
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
      log.WithFields(logrus.Fields{ "status":status }).Debug("Read humans failed")
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    if responses == nil {
      // Not found
      c.AbortWithStatus(http.StatusNotFound)
      return
    }

    var humans idp.ReadHumansResponse
    reqStatus, reqErrors := bulky.Unmarshal(0, responses, &humans)

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

      log.WithFields(logrus.Fields{ "status":reqStatus, "errors":strings.Join(errors, ", ") }).Debug("Unmarshal ReadHumansResponse failed")
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    human := humans[0]
    recoverRequests := []idp.CreateHumansRecoverRequest{ {Id: human.Id, RedirectTo: form.RedirectTo} }
    status, responses, err = idp.RecoverHumans(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.humans.recover"), recoverRequests)
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
      log.WithFields(logrus.Fields{ "status":status }).Debug("Read human recover failed")
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    if responses == nil {
      // Not found
      c.AbortWithStatus(http.StatusNotFound)
      return
    }

    var recover idp.CreateHumansRecoverResponse
    reqStatus, reqErrors = bulky.Unmarshal(0, responses, &recover)

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

      log.WithFields(logrus.Fields{ "status":reqStatus, "errors":strings.Join(errors, ", ") }).Debug("Unmarshal CreateHumansRecoverResponse failed")
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    if reqStatus == http.StatusOK {

      // Cleanup session
      //session.Delete("recover.email")
      //session.Delete("recover.errors")
      session.Clear()
      err = session.Save()
      if err != nil {
        log.Debug(err.Error())
      }

      log.WithFields(logrus.Fields{ "redirect_to": recover.RedirectTo }).Debug("Redirecting");
      c.Redirect(http.StatusFound, recover.RedirectTo)
      c.Abort()
      return
    }

    errors["email"] = append(errors["email"], "Not Found")
    session.AddFlash(errors, "recover.errors")
    err = session.Save()
    if err != nil {
      log.Debug(err.Error())
    }

    log.WithFields(logrus.Fields{"redirect_to": submitUrl}).Debug("Redirecting")
    c.Redirect(http.StatusFound, submitUrl)
    c.Abort()
    return
  }
  return gin.HandlerFunc(fn)
}
