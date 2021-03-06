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
  idp "github.com/opensentry/idp/client"

  "github.com/opensentry/idpui/app"
  "github.com/opensentry/idpui/config"
  "github.com/opensentry/idpui/utils"
  "github.com/opensentry/idpui/validators"

  bulky "github.com/charmixer/bulky/client"
)

type claimEmailForm struct {
  Email string `form:"email" validate:"required,email,notblank"`
}

func ShowClaimEmail(env *app.Environment) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(env.Constants.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowClaimEmail",
    })

    session := sessions.DefaultMany(c, env.Constants.SessionStoreKey)

    var err error
    var invite *idp.Invite

    id := c.Query("id")
    if id != "" {
      idpClient := app.IdpClientUsingClientCredentials(env, c)

      newChallengeSession := app.ChallengeSession{
        RedirectToOnSuccess: config.GetString("idpui.public.url") + config.GetString("idpui.public.endpoints.register"),
      }
      challengeSession, err := app.StartChallengeSession(env, c, newChallengeSession)
      if err != nil {
        log.Debug(err.Error())
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }

      claimRequest := []idp.CreateInvitesClaimRequest{ {Id:id, RedirectTo:challengeSession.RedirectToOnSuccess, TTL: 86400} }
      status, responses, err := idp.CreateInvitesClaim(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.invites.claim"), claimRequest)
      if err != nil {
        log.Debug(err.Error())
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }

      if status == http.StatusOK {

        var claimResp idp.CreateInvitesClaimResponse
        status, restErr := bulky.Unmarshal(0, responses, &claimResp)
        if len(restErr) > 0 {
          for _,e := range restErr {
            log.Debug("Rest error: " + e.Error)
          }
          c.AbortWithStatus(http.StatusInternalServerError)
          return
        }

        if status == http.StatusOK {

          // Cleanup session
          // session.Delete("register.fields")
          // session.Delete("register.errors")
          session.Clear()
          err = session.Save()
          if err != nil {
            log.Debug(err.Error())
          }

          redirectTo := claimResp.RedirectTo
          log.WithFields(logrus.Fields{"redirect_to": redirectTo}).Debug("Redirecting")
          c.Redirect(http.StatusFound, redirectTo)
          c.Abort()
          return
        }

      }

      // TODO: Better error handling
      log.WithFields(logrus.Fields{ "id":id }).Debug("Not Found")
      c.AbortWithStatus(http.StatusNotFound)
      return
    }

    var email string
    var errorEmail string

    // Retain the values that was submittet
    rf := session.Flashes("register.fields")
    if len(rf) > 0 {
      registerFields := rf[0].(map[string][]string)
      for k, v := range registerFields {
        if k == "email" && len(v) > 0 { email = strings.Join(v, ", ") }
      }
    }

    errors := session.Flashes("register.errors")
    err = session.Save() // Remove flashes read, and save submit fields
    if err != nil {
      log.Debug(err.Error())
    }

    if len(errors) > 0 {
      errorsMap := errors[0].(map[string][]string)
      for k, v := range errorsMap {
        if k == "email" && len(v) > 0 { errorEmail = strings.Join(v, ", ") }
      }
    }

    c.HTML(200, "claimemail.html", gin.H{
      "title": "Claim",
      "links": []map[string]string{
        {"href": "/public/css/credentials.css"},
      },
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "provider": config.GetString("provider.name"),
      "provideraction": "Claim an identity in the system with an email",
      "claimUrl": config.GetString("idpui.public.endpoints.claim"),
      "loginUrl": config.GetString("idpui.public.endpoints.login"),
      "invite": invite,
      "email": email,
      "errorEmail": errorEmail,
    })
  }
  return gin.HandlerFunc(fn)
}

func SubmitClaimEmail(env *app.Environment) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(env.Constants.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "SubmitClaimEmail",
    })

    var form claimEmailForm
    err := c.Bind(&form)
    if err != nil {
      c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      return
    }

    submitUrl, err := utils.FetchSubmitUrlFromRequest(c.Request, nil)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    session := sessions.DefaultMany(c, env.Constants.SessionStoreKey)

    // Save values if submit fails
    registerFields := make(map[string][]string)
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

    if form.Email != "" {

      idpClient := app.IdpClientUsingClientCredentials(env, c)

      var inviteId string

      inviteRequest := []idp.ReadInvitesRequest{ {Email: form.Email} }
      status, responses, err := idp.ReadInvites(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.invites.collection"), inviteRequest)
      if err != nil {
        log.Debug(err.Error())
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }
      if status == 200 {
        var resp idp.ReadInvitesResponse
        status, _ := bulky.Unmarshal(0, responses, &resp)
        if status == 200 {
          invite := resp[0]
          inviteId = invite.Id
        }
      } else {

        // FIXME: Better error handling please
        c.AbortWithStatus(status)
        return

      }

      if inviteId == "" {

        inviteRequest := []idp.CreateInvitesRequest{ {Email: form.Email} }
        status, responses, err := idp.CreateInvites(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.invites.collection"), inviteRequest)
        if err != nil {
          log.Debug(err.Error())
          c.AbortWithStatus(http.StatusInternalServerError)
          return
        }
        if status == 200 {
          var invResp idp.CreateInvitesResponse
          status, _ := bulky.Unmarshal(0, responses, &invResp)
          if status == 200 {
            inviteId = invResp.Id
          }

        } else {

          // FIXME: Better error handling please
          c.AbortWithStatus(status)
          return

        }

      }

      if inviteId != "" {

        newChallengeSession := app.ChallengeSession{
          RedirectToOnSuccess: config.GetString("idpui.public.url") + config.GetString("idpui.public.endpoints.register"),
        }
        challengeSession, err := app.StartChallengeSession(env, c, newChallengeSession)
        if err != nil {
          log.Debug(err.Error())
          c.AbortWithStatus(http.StatusInternalServerError)
          return
        }

        claimRequest := []idp.CreateInvitesClaimRequest{ {Id:inviteId, RedirectTo:challengeSession.RedirectToOnSuccess, TTL: 86400} }
        status, responses, err := idp.CreateInvitesClaim(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.invites.claim"), claimRequest)
        if err != nil {
          log.Debug(err.Error())
          c.AbortWithStatus(http.StatusInternalServerError)
          return
        }
        if status == 200 {
          var challengeResp idp.CreateInvitesClaimResponse
          status, _ := bulky.Unmarshal(0, responses, &challengeResp)
          if status == 200 {

            // Cleanup session
            // session.Delete("register.fields")
            // session.Delete("register.errors")
            session.Clear()
            err = session.Save()
            if err != nil {
              log.Debug(err.Error())
            }

            redirectTo := challengeResp.RedirectTo
            log.WithFields(logrus.Fields{"redirect_to": redirectTo}).Debug("Redirecting")
            c.Redirect(http.StatusFound, redirectTo)
            c.Abort()
            return
          }

        } else {

          // FIXME: Better error handling please
          c.AbortWithStatus(status)
          return

        }

      }

      errors["email"] = append(errors["email"], "Already registered")
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