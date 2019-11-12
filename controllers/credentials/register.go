package credentials

import (
  "strings"
  "net/http"
  "net/url"
  "reflect"
  "errors"
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

type registrationForm struct {
    Challenge       string `form:"challenge"          validate="required,uuid,notblank"`
    State           string `form:"state"              validate="required,notblank"`
    Name            string `form:"display-name"       validate:"required,notblank"`
    Username        string `form:"username,omitempty" validate:"omitempty,notblank"`
    Password        string `form:"password"           validate:"required,notblank"`
    PasswordRetyped string `form:"password_retyped"   validate:"required,notblank"`
}

const REGISTER_ERRORS = "register.errors"
const REGISTER_FIELDS = "register.fields"

func ShowRegistration(env *app.Environment) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(env.Constants.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowRegistration",
    })

    var err error

    var username string
    var displayName string

    state := c.Query("state")
    if state == "" {
      log.Debug("Missing state in query")
      c.AbortWithStatus(http.StatusBadRequest)
      return
    }

    session := sessions.DefaultMany(c, env.Constants.SessionStoreKey)
    v := session.Get(env.Constants.SessionClaimStateKey)
    if v == nil {
      log.WithFields(logrus.Fields{ "key":env.Constants.SessionClaimStateKey }).Debug("Request not initiated by app. Hint: Missing session state")
      c.AbortWithStatus(http.StatusBadRequest)
      return
    }
    sessionState := v.(string)

    if state != sessionState {
      log.WithFields(logrus.Fields{ "key":env.Constants.SessionClaimStateKey }).Debug("Request did not originate from app. Hint: session state and request state differs")
      c.AbortWithStatus(http.StatusBadRequest)
      return
    }

    challengeId := c.Query(EMAIL_CHALLENGE_KEY)
    if challengeId != "" {

      idpClient := app.IdpClientUsingClientCredentials(env, c)

      challenge, err := fetchChallenge(idpClient, challengeId)
      if err != nil {
        log.Debug(err.Error())
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }

      if challenge != nil {
        invite, err := fetchInvites(idpClient, challenge.Subject)
        if err != nil {
          log.Debug(err.Error())
          c.AbortWithStatus(http.StatusInternalServerError)
          return
        }

        if invite != nil && invite.Username != "" {
          username = invite.Username
        }
      }

    }

    // Retain the values that was submittet
    rf := session.Flashes(REGISTER_FIELDS)
    if len(rf) > 0 {
      registerFields := rf[0].(map[string][]string)
      for k, v := range registerFields {

        if k == "challenge" && len(v) > 0 {
          challengeId = strings.Join(v, ", ")
        }

        if k == "state" && len(v) > 0 {
          state = strings.Join(v, ", ")
        }

        if k == "username" && len(v) > 0 {
          username = strings.Join(v, ", ")
        }

        if k == "display-name" && len(v) > 0 {
          displayName = strings.Join(v, ", ")
        }
      }
    }


    errors := session.Flashes(REGISTER_ERRORS)
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
      "state": state,
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

func SubmitRegistration(env *app.Environment) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(env.Constants.LogKey).(*logrus.Entry)
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

    q := url.Values{}
    q.Add("state", form.State)
    q.Add(EMAIL_CHALLENGE_KEY, form.Challenge)

    submitUrl, err := utils.FetchSubmitUrlFromRequest(c.Request, &q)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    if form.State == "" {
      log.Debug("Missing state")
      c.AbortWithStatus(http.StatusBadRequest)
      return
    }

    session := sessions.DefaultMany(c, env.Constants.SessionStoreKey)
    v := session.Get(env.Constants.SessionClaimStateKey)
    if v == nil {
      log.WithFields(logrus.Fields{ "key":env.Constants.SessionClaimStateKey }).Debug("Request not initiated by app. Hint: Missing session state")
      c.AbortWithStatus(http.StatusBadRequest)
      return
    }
    sessionState := v.(string)

    if form.State != sessionState {
      log.WithFields(logrus.Fields{ "key":env.Constants.SessionClaimStateKey }).Debug("Request did not originate from app. Hint: session state and request state differs")
      c.AbortWithStatus(http.StatusBadRequest)
      return
    }

    // Save values if submit fails
    registerFields := make(map[string][]string)
    registerFields["challenge"] = append(registerFields["challenge"], form.Challenge)
    registerFields["state"] = append(registerFields["challenge"], form.State)
    registerFields["display-name"] = append(registerFields["display-name"], form.Name)
    registerFields["username"] = append(registerFields["username"], form.Username)

    session.AddFlash(registerFields, REGISTER_FIELDS)
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
      session.AddFlash(errors, REGISTER_ERRORS)
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
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }

      if status != http.StatusOK {
        log.WithFields(logrus.Fields{ "status":status }).Debug("Request failed")
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }

      var resp idp.CreateHumansResponse
      status, restErr := bulky.Unmarshal(0, responses, &resp)
      if len(restErr) <= 0 {

        if status == http.StatusOK {
          // Cleanup session
          // session.Delete(env.Constants.SessionClaimStateKey)
          // session.Delete(REGISTER_FIELDS)
          // session.Delete(REGISTER_ERRORS)
          session.Clear()

          // Propagate email to authenticate controller
          session.AddFlash(resp.Email, "authenticate.email")

          err = session.Save()
          if err != nil {
            log.Debug(err.Error())
          }

          // Registration successful, return to create new ones, but with success message
          redirectTo := config.GetString("meui.public.url") + config.GetString("meui.public.endpoints.profile")
          log.WithFields(logrus.Fields{"redirect_to": redirectTo}).Debug("Redirecting")
          c.Redirect(http.StatusFound, redirectTo)
          c.Abort()
          return
        }

      } else {

        for _,e := range restErr {
          errors["username"] = append(errors["username"], e.Error)
        }

      }

    } else {

      errors["password_retyped"] = append(errors["password_retyped"], "No Match")

    }

    if len(errors) > 0 {
      session.AddFlash(errors, REGISTER_ERRORS)
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
  } else {

    if status == 403 {
      return nil, errors.New("Access to read challenges denied")
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
  } else {

    if status == 403 {
      return nil, errors.New("Access to read invites denied")
    }

  }

  return nil, nil
}
