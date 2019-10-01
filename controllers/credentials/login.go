package credentials

import (
  "net/url"
  "net/http"
  "strings"
  "reflect"
  "fmt"
  "gopkg.in/go-playground/validator.v9"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"
  "github.com/gin-contrib/sessions"
  idp "github.com/charmixer/idp/client"

  "github.com/charmixer/idpui/app"
  "github.com/charmixer/idpui/config"
  "github.com/charmixer/idpui/environment"
  "github.com/charmixer/idpui/validators"
)

type authenticationForm struct {
  Challenge string `form:"challenge" binding:"required"`
  Username string `form:"username" binding:"required" validate:"required,notblank"`
  Password string `form:"password" binding:"required" validate:"required,notblank"`
}

func ShowLogin(env *environment.State) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowLogin",
    })

    loginChallenge := c.Query("login_challenge")
    if loginChallenge == "" {
      // User is visiting login page as the first part of the process, probably meaning. Want to view profile or change it.
      // IdpUi should ask hydra for a challenge to login
      initUrl, err := app.StartAuthenticationSession(env, c, log)
      if err != nil {
        log.Debug(err.Error())
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        c.Abort()
        return
      }
      log.WithFields(logrus.Fields{"redirect_to": initUrl.String()}).Debug("Redirecting")
      c.Redirect(http.StatusFound, initUrl.String())
      c.Abort()
      return
    }

    idpClient := app.IdpClientUsingClientCredentials(env, c)

    var authenticateRequest []idp.CreateHumansAuthenticateRequest
    otpChallenge := c.Query("otp_challenge")
    if otpChallenge != "" {
      authenticateRequest = append(authenticateRequest, idp.CreateHumansAuthenticateRequest{
        Challenge: loginChallenge,
        OtpChallenge: otpChallenge,
      })
    } else {
      authenticateRequest = append(authenticateRequest, idp.CreateHumansAuthenticateRequest{
        Challenge: loginChallenge,
      })
    }

    _, authenticateResponse, err := idp.CreateHumansAuthenticate(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.humans.authenticate"), authenticateRequest)
    if err != nil {
      log.WithFields(logrus.Fields{ "challenge":loginChallenge }).Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    if authenticateResponse == nil {
      log.WithFields(logrus.Fields{ "challenge":loginChallenge }).Debug("Not Found")
      c.AbortWithStatus(http.StatusNotFound)
      return
    }

    _, obj, _ := idp.UnmarshalResponse(0, authenticateResponse)
    if obj != nil {

      auth := obj.(idp.HumanAuthentication)

      if auth.Authenticated {
        log.WithFields(logrus.Fields{"authenticated":auth.Authenticated, "redirect_to":auth.RedirectTo}).Debug("Redirecting")
        c.Redirect(http.StatusFound, auth.RedirectTo)
        c.Abort()
        return
      }

      session := sessions.Default(c)

      // Retain the values that was submittet, except passwords!
      var username string
      fau := session.Flashes("authenticate.username")
      if fau != nil {
        username = fmt.Sprintf("%s", fau[0])
      }

      errors := session.Flashes("authenticate.errors")
      err = session.Save() // Remove flashes read, and save submit fields
      if err != nil {
        log.Debug(err.Error())
      }

      var errorUsername string
      var errorPassword string

      if len(errors) > 0 {
        errorsMap := errors[0].(map[string][]string)
        for k, v := range errorsMap {

          if k == "username" && len(v) > 0 {
            errorUsername = strings.Join(v, ", ")
          }
          if k == "password" && len(v) > 0 {
            errorPassword = strings.Join(v, ", ")
          }

        }
      }

      c.HTML(200, "login.html", gin.H{
        "links": []map[string]string{
          {"href": "/public/css/credentials.css"},
        },
        "title": "Authenticate",
        csrf.TemplateTag: csrf.TemplateField(c.Request),
        "provider": "Identity Provider",
        "provideraction": "Identify yourself to gain access to your profile",
        "challenge": loginChallenge,
        "username": username,
        "errorUsername": errorUsername,
        "errorPassword": errorPassword,
        "loginUrl": config.GetString("idpui.public.endpoints.login"),
        "recoverUrl": config.GetString("idpui.public.endpoints.recover"),
        "registerUrl": config.GetString("idpui.public.endpoints.register"),
      })
      return
    }

    // Deny by default
    log.WithFields(logrus.Fields{ "challenge":loginChallenge }).Debug("Not Found")
    c.AbortWithStatus(http.StatusNotFound)
  }
  return gin.HandlerFunc(fn)
}

func SubmitLogin(env *environment.State) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "SubmitLogin",
    })

    var form authenticationForm
    err := c.Bind(&form)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      return
    }

    session := sessions.Default(c)

    // Save value if submit fails
    session.AddFlash(form.Username, "authenticate.username")
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
        case "email":
            errors[name] = append(errors[name], "Not an E-mail")
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
      session.AddFlash(errors, "authenticate.errors")
      err = session.Save()
      if err != nil {
        log.Debug(err.Error())
      }

      redirectTo := c.Request.URL.RequestURI() + "?login_challenge=" + form.Challenge
      log.WithFields(logrus.Fields{"redirect_to": redirectTo}).Debug("Redirecting")
      c.Redirect(http.StatusFound, redirectTo)
      c.Abort();
      return
    }

    idpClient := app.IdpClientUsingClientCredentials(env, c)

    identityRequest := []idp.ReadHumansRequest{ {Username: form.Username} }
    _, humans, err := idp.ReadHumans(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.humans.collection"), identityRequest)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    if humans == nil {
      errors["username"] = append(errors["username"], "Not found")
    } else {

      status, obj, _ := idp.UnmarshalResponse(0, humans)
      if status == 200 && obj != nil {

        human := obj.(idp.Human)

        log.WithFields(logrus.Fields{ "id":human.Id, "username":human.Username, "email":human.Email} ).Debug("Human found")

        // Ask idp to authenticate the user
        authenticateRequest := []idp.CreateHumansAuthenticateRequest{{
          Id: human.Id,
          Password: form.Password,
          Challenge: form.Challenge,
        }}
        _, authenticateResponse, err := idp.CreateHumansAuthenticate(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.humans.authenticate"), authenticateRequest)
        if err != nil {
          log.WithFields(logrus.Fields{ "id":human.Id, "challenge":form.Challenge }).Debug(err.Error())
          c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
          return
        }

        if authenticateResponse == nil {
          log.WithFields(logrus.Fields{ "challenge":form.Challenge, "id":human.Id }).Debug("Not Found")
          c.AbortWithStatus(http.StatusNotFound)
          return
        }

        status, obj, _ := idp.UnmarshalResponse(0, authenticateResponse)
        if status == 200 && obj != nil {

          auth := obj.(idp.HumanAuthentication)

          // User authenticated, redirect
          if auth.Authenticated == true {

            // Cleanup session
            session.Delete("authenticate.username")
            session.Delete("authenticate.errors")

            err = session.Save()
            if err != nil {
              log.Debug(err.Error())
            }

            log.WithFields(logrus.Fields{ "id":auth.Id, "authenticated":auth.Authenticated, "totp_required":auth.TotpRequired, "redirect_to":auth.RedirectTo }).Debug("Redirecting")
            c.Redirect(http.StatusFound, auth.RedirectTo)
            c.Abort()
            return
          }

          // Deny by default
          if auth.IsPasswordInvalid == true {
            errors["password"] = append(errors["password"], "Invalid")
          }
        }

      }

    }
    session.AddFlash(errors, "authenticate.errors")
    err = session.Save()
    if err != nil {
      log.Debug(err.Error())
    }

    u, err := url.Parse( c.Request.RequestURI )
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }
    q := u.Query()
    if q.Get("login_challenge") == "" {
      q.Add("login_challenge", form.Challenge)
    }
    u.RawQuery = q.Encode()

    redirectTo := u.String()
    log.WithFields(logrus.Fields{"redirect_to": redirectTo}).Debug("Redirecting")
    c.Redirect(http.StatusFound, redirectTo)
    c.Abort()
  }
  return gin.HandlerFunc(fn)
}

