package credentials

import (
  "strings"
  "net/http"
  "reflect"
  "gopkg.in/go-playground/validator.v9"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"
  "github.com/gin-contrib/sessions"
  idp "github.com/charmixer/idp/client"

  "github.com/charmixer/idpui/app"
  "github.com/charmixer/idpui/config"
  "github.com/charmixer/idpui/environment"
  "github.com/charmixer/idpui/utils"
  "github.com/charmixer/idpui/validators"
)

type registrationForm struct {
    Username string `form:"username" binding:"required" validate:"required,notblank"`
    Name string `form:"display-name" binding:"required" validate:"required,notblank"`
    Email string `form:"email" binding:"required" validate:"required,email"`
    Password string `form:"password" binding:"required" validate:"required,notblank"`
    PasswordRetyped string `form:"password_retyped" binding:"required" validate:"required,notblank"`
}

func ShowRegistration(env *environment.State) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowRegistration",
    })

    session := sessions.Default(c)

    // Retain the values that was submittet, except passwords ?!
    var username string
    var displayName string
    var email string
    rf := session.Flashes("register.fields")
    if len(rf) > 0 {
      registerFields := rf[0].(map[string][]string)
      for k, v := range registerFields {
        if k == "username" && len(v) > 0 {
          username = strings.Join(v, ", ")
        }

        if k == "email" && len(v) > 0 {
          email = strings.Join(v, ", ")
        }

        if k == "display-name" && len(v) > 0 {
          displayName = strings.Join(v, ", ")
        }
      }
    }

    var errorUsername string
    var errorPassword string
    var errorPasswordRetyped string
    var errorEmail string
    var errorDisplayName string

    errors := session.Flashes("register.errors")
    err := session.Save() // Remove flashes read, and save submit fields
    if err != nil {
      log.Debug(err.Error())
    }

    if len(errors) > 0 {
      errorsMap := errors[0].(map[string][]string)
      for k, v := range errorsMap {
        if k == "username" && len(v) > 0 {
          errorUsername = strings.Join(v, ", ")
        }

        if k == "password" && len(v) > 0 {
          errorPassword = strings.Join(v, ", ")
        }

        if k == "password_retyped" && len(v) > 0 {
          errorPasswordRetyped = strings.Join(v, ", ")
        }

        if k == "email" && len(v) > 0 {
          errorEmail = strings.Join(v, ", ")
        }

        if k == "display-name" && len(v) > 0 {
          errorDisplayName = strings.Join(v, ", ")
        }
      }
    }

    c.HTML(200, "register.html", gin.H{
      "title": "Register",
      "links": []map[string]string{
        {"href": "/public/css/credentials.css"},
      },
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "provider": "Identity Provider",
      "provideraction": "Register for an identity in the system",
      "registerUrl": config.GetString("idpui.public.endpoints.register"),
      "loginUrl": config.GetString("idpui.public.endpoints.login"),
      "username": username,
      "displayName": displayName,
      "email": email,
      "errorUsername": errorUsername,
      "errorPassword": errorPassword,
      "errorPasswordRetyped": errorPasswordRetyped,
      "errorEmail": errorEmail,
      "errorDisplayName": errorDisplayName,
    })
  }
  return gin.HandlerFunc(fn)
}

func SubmitRegistration(env *environment.State) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "SubmitRegistration",
    })

    var form registrationForm
    err := c.Bind(&form)
    if err != nil {
      // Do better error handling in the application.
      c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    session := sessions.Default(c)

    // Save values if submit fails
    registerFields := make(map[string][]string)
    registerFields["username"] = append(registerFields["username"], form.Username)
    registerFields["display-name"] = append(registerFields["display-name"], form.Name)
    registerFields["email"] = append(registerFields["email"], form.Email)

    session.AddFlash(registerFields, "register.fields")
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

    if form.Password != form.PasswordRetyped {
      errors["password_retyped"] = append(errors["password_retyped"], "No Match")
    }

    if len(errors) > 0 {
      session.AddFlash(errors, "register.errors")
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

    if form.Password == form.PasswordRetyped { // Just for safety is caught in the input error detection.

      idpClient := app.IdpClientUsingClientCredentials(env, c)

      humanRequest := []idp.CreateHumansRequest{{
        Username: form.Username,
        Email: form.Email,
        Password: form.Password,
        Name: form.Name,
      }}
      _, _, err := idp.CreateHumans(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.humans.collection"), humanRequest)
      if err != nil {
        log.Debug(err.Error())
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        c.Abort()
        return
      }

      session := sessions.Default(c)

      // Cleanup session
      session.Delete("register.fields")
      session.Delete("register.errors")

      // Propagate username to authenticate controller
      session.AddFlash(form.Username, "authenticate.username")

      err = session.Save()
      if err != nil {
        log.Debug(err.Error())
      }

      // Registration successful, return to create new ones, but with success message
      redirectTo := config.GetString("idpui.public.url") + config.GetString("idpui.public.endpoints.profile")
      log.WithFields(logrus.Fields{"redirect_to": redirectTo}).Debug("Redirecting")
      c.Redirect(http.StatusFound, redirectTo)
      c.Abort()
      return
    }

    // Deny by default. Failed to fill in the form correctly.
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
