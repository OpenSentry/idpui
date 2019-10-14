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

  bulky "github.com/charmixer/bulky/client"
)

type registrationForm struct {
    Challenge       string `form:"challenge"          validate="required,uuid,notblank"`
    Name            string `form:"display-name"       validate:"required,notblank"`
    Username        string `form:"username,omitempty" validate:"omitempty,notblank"`
    Password        string `form:"password"           validate:"required,notblank"`
    PasswordRetyped string `form:"password_retyped"   validate:"required,notblank"`
}

func ShowRegistration(env *environment.State) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowRegistration",
    })

    var err error

    var username string
    var displayName string

    challengeId := c.Query("email_challenge")
    if challengeId != "" {

      idpClient := app.IdpClientUsingClientCredentials(env, c)

      challenge, err := fetchChallenge(idpClient, challengeId)
      if err != nil {
        log.Debug(err.Error())
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }

      invite, err := fetchInvites(idpClient, challenge.Subject)
      if err != nil {
        log.Debug(err.Error())
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }

      if invite.Username != "" {
        username = invite.Username
      }

    }

    session := sessions.Default(c)

    // Retain the values that was submittet
    rf := session.Flashes("register.fields")
    if len(rf) > 0 {
      registerFields := rf[0].(map[string][]string)
      for k, v := range registerFields {

        if k == "challenge" && len(v) > 0 {
          challengeId = strings.Join(v, ", ")
        }

        if k == "username" && len(v) > 0 {
          username = strings.Join(v, ", ")
        }

        if k == "display-name" && len(v) > 0 {
          displayName = strings.Join(v, ", ")
        }
      }
    }


    errors := session.Flashes("register.errors")
    err = session.Save() // Remove flashes read, and save submit fields
    if err != nil {
      log.Debug(err.Error())
    }

    var errorUsername string
    var errorPassword string
    var errorPasswordRetyped string
    var errorDisplayName string

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
      "challenge": challengeId,
      "username": username,
      "displayName": displayName,
      "errorUsername": errorUsername,
      "errorPassword": errorPassword,
      "errorPasswordRetyped": errorPasswordRetyped,
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

    var err error

    var form registrationForm
    err = c.Bind(&form)
    if err != nil {
      // Do better error handling in the application.
      c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    submitUrl, err := utils.FetchSubmitUrlFromRequest(c.Request, nil)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    session := sessions.Default(c)

    // Save values if submit fails
    registerFields := make(map[string][]string)
    registerFields["challenge"] = append(registerFields["challenge"], form.Challenge)
    registerFields["display-name"] = append(registerFields["display-name"], form.Name)
    registerFields["username"] = append(registerFields["username"], form.Username)

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

      log.WithFields(logrus.Fields{"redirect_to": submitUrl}).Debug("Redirecting")
      c.Redirect(http.StatusFound, submitUrl)
      c.Abort()
      return
    }

    if form.Password == form.PasswordRetyped { // Just for safety is caught in the input error detection.

      idpClient := app.IdpClientUsingClientCredentials(env, c)

      challenge, err := fetchChallenge(idpClient, form.Challenge)
      if err != nil {
        log.Debug(err.Error())
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }
      
      var emailConfirmedAt int64 = 0
      if challenge.VerifiedAt > 0 { // FIXME add challenge type check
        emailConfirmedAt = challenge.VerifiedAt
      }

      humanRequest := []idp.CreateHumansRequest{ {Id:challenge.Subject, Password:form.Password, Name:form.Name, Username:form.Username, EmailConfirmedAt:emailConfirmedAt} }
      status, responses, err := idp.CreateHumans(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.humans.collection"), humanRequest)
      if err != nil {
        log.Debug(err.Error())
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        c.Abort()
        return
      }

      if status == 200 {

        var resp idp.CreateHumansResponse
        status, restErr := bulky.Unmarshal(0, responses, &resp)
        if status == 200 {
          // Cleanup session
          session.Delete("register.fields")
          session.Delete("register.errors")

          // Propagate email to authenticate controller
          session.AddFlash(resp.Email, "authenticate.email")

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

        if restErr != nil {
          for _,e := range restErr {
            errors["username"] = append(errors["username"], e.Error)
          }
        }
      }

    } else {

      errors["password_retyped"] = append(errors["password_retyped"], "No Match")

    }

    if len(errors) > 0 {
      session.AddFlash(errors, "register.errors")
      err = session.Save()
      if err != nil {
        log.Debug(err.Error())
      }
    }

    // Deny by default.
    log.WithFields(logrus.Fields{"redirect_to": submitUrl}).Debug("Redirecting")
    c.Redirect(http.StatusFound, submitUrl)
    c.Abort()
  }
  return gin.HandlerFunc(fn)
}

func fetchChallenge(idpClient *idp.IdpClient, challenge string) (*idp.Challenge, error) {

  requests := []idp.ReadChallengesRequest{ {OtpChallenge: challenge} }
  status, responses, err := idp.ReadChallenges(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.challenges.collection"), requests)
  if err != nil {
    return nil, err
  }

  if status == 200 {
    var resp idp.ReadChallengesResponse
    status, _ := bulky.Unmarshal(0, responses, &resp)
    if status == 200 {
      challenge := &resp[0]
      return challenge, nil
    }
  }

  return nil, nil
}

func fetchInvites(idpClient *idp.IdpClient, id string) (*idp.Invite, error) {

  requests := []idp.ReadInvitesRequest{ {Id: id} }
  status, responses, err := idp.ReadInvites(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.invites.collection"), requests)
  if err != nil {
    return nil, err
  }

  if status == 200 {
    var resp idp.ReadInvitesResponse
    status, _ := bulky.Unmarshal(0, responses, &resp)
    if status == 200 {
      invite := &resp[0]
      return invite, nil
    }
  }

  return nil, nil
}
