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
  "golang.org/x/oauth2"
  oidc "github.com/coreos/go-oidc"
  idp "github.com/charmixer/idp/client"

  "github.com/charmixer/idpui/config"
  "github.com/charmixer/idpui/environment"
  "github.com/charmixer/idpui/utils"
  "github.com/charmixer/idpui/validators"
)

type passwordForm struct {
  Password string `form:"password" binding:"required" validate:"required,notblank"`
  PasswordRetyped string `form:"password_retyped" binding:"required" validate:"required,notblank"`
}

func ShowPassword(env *environment.State) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowPassword",
    })

    session := sessions.Default(c)

    var idToken *oidc.IDToken
    idToken = session.Get(environment.SessionIdTokenKey).(*oidc.IDToken)
    if idToken == nil {
      c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Missing id_token in session"})
      return
    }

    errors := session.Flashes("password.errors")
    err := session.Save() // Remove flashes read, and save submit fields
    if err != nil {
      log.Debug(err.Error())
    }

    var errorPassword string
    var errorPasswordRetyped string

    if len(errors) > 0 {
      errorsMap := errors[0].(map[string][]string)
      for k, v := range errorsMap {

        if k == "password" && len(v) > 0 {
          errorPassword = strings.Join(v, ", ")
        }

        if k == "password_retyped" && len(v) > 0 {
          errorPasswordRetyped = strings.Join(v, ", ")
        }

      }
    }

    c.HTML(http.StatusOK, "password.html", gin.H{
      "title": "Password",
      "links": []map[string]string{
        {"href": "/public/css/credentials.css"},
      },
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "provider": "Identity Provider",
      "provideraction": "Change your password",
      "id": idToken.Subject,
      "passwordUrl": config.GetString("idpui.public.endpoints.password"),
      "errorPassword": errorPassword,
      "errorPasswordRetyped": errorPasswordRetyped,
    })
  }
  return gin.HandlerFunc(fn)
}

func SubmitPassword(env *environment.State) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "SubmitPassword",
    })

    var form passwordForm
    err := c.Bind(&form)
    if err != nil {
      // Do better error handling in the application.
      c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      c.Abort()
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

    if form.Password != form.PasswordRetyped {
      errors["password_retyped"] = append(errors["password_retyped"], "No Match")
    }


    if len(errors) > 0 {
      session.AddFlash(errors, "password.errors")
      err = session.Save()
      if err != nil {
        log.Debug(err.Error())
      }

      submitUrl, err := utils.FetchSubmitUrlFromRequest(c.Request)
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

      var idToken *oidc.IDToken
      idToken = session.Get(environment.SessionIdTokenKey).(*oidc.IDToken)
      if idToken == nil {
        c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "Missing id_token"})
        return
      }

      log.WithFields(logrus.Fields{"fixme": 1}).Debug("Figure out if we are to use client credentials to communicate from ui to api or we wanna use the user authorized access token in ui to access api")

      var accessToken *oauth2.Token
      accessToken = session.Get(environment.SessionTokenKey).(*oauth2.Token)
      idpClient := idp.NewIdpClientWithUserAccessToken(env.HydraConfig, accessToken)

      passwordRequest := &idp.IdentitiesPasswordRequest{
        Id: idToken.Subject,
        Password: form.Password,
      }
      _ /* updatedIdentity */, err := idp.UpdateIdentityPassword(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.password"), passwordRequest)
      if err != nil {
        log.Debug(err.Error())
        c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
      }

      log.WithFields(logrus.Fields{"fixme":1}).Debug("Redirect to where we came from")
      redirectTo := "/me"
      log.WithFields(logrus.Fields{"redirect_to": redirectTo}).Debug("Redirecting")
      c.Redirect(http.StatusFound, redirectTo)
      c.Abort()
      return
    }

    // Deny by default. Failed to fill in the form correctly.
    submitUrl, err := utils.FetchSubmitUrlFromRequest(c.Request)
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
