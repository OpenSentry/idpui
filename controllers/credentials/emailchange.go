package credentials

import (
  //"fmt"
  "net/http"
  "strings"
  "reflect"
  "gopkg.in/go-playground/validator.v9"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"
  "github.com/gin-contrib/sessions"
  "golang.org/x/oauth2"

  idp "github.com/opensentry/idp/client"

  "github.com/opensentry/idpui/app"
  "github.com/opensentry/idpui/config"
  "github.com/opensentry/idpui/utils"
  "github.com/opensentry/idpui/validators"

  bulky "github.com/charmixer/bulky/client"
)

type emailChangeForm struct {
  AccessToken string `form:"access_token" binding:"required" validate:"required,notblank"`
  Id string `form:"id" binding:"required" validate:"required,uuid"`
  //RedirectTo string `form:"redirect_to" binding:"required" validate:"required,uri"`
  Email string `form:"email" binding:"required" validate:"required,email"`
}

func ShowEmailChange(env *app.Environment) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(env.Constants.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowEmailChange",
    })

    identity := app.GetIdentity(env, c)
    if identity == nil {
      log.Debug("Missing Identity")
      c.AbortWithStatus(http.StatusForbidden)
      return
    }

    session := sessions.DefaultMany(c, env.Constants.SessionStoreKey)

    errors := session.Flashes(EMAILCHANGE_ERRORS)
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

    token := app.AccessToken(env, c)

    // c.Header("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))
    c.HTML(http.StatusOK, "emailchange.html", gin.H{
      "title": "Email",
      "links": []map[string]string{
        {"href": "/public/css/credentials.css"},
      },
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "provider": config.GetString("provider.name"),
      "provideraction": "Change your email",
      "access_token": token.AccessToken,
      "id": identity.Id,
      "name": identity.Name,
      "email": identity.Email,
      "emailChangeUrl": config.GetString("idpui.public.url") + config.GetString("idpui.public.endpoints.emailchange"),
      "errorEmail": errorEmail,
    })
  }
  return gin.HandlerFunc(fn)
}

func SubmitEmailChange(env *app.Environment) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(env.Constants.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "SubmitEmailChange",
    })

    var form emailChangeForm
    err := c.Bind(&form)
    if err != nil {
      c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      c.Abort()
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
      session.AddFlash(errors, EMAILCHANGE_ERRORS)
      err = session.Save()
      if err != nil {
        log.Debug(err.Error())
      }

      log.WithFields(logrus.Fields{"errors":len(errors), "redirect_to": submitUrl}).Debug("Redirecting")
      c.Redirect(http.StatusFound, submitUrl)
      c.Abort()
      return
    }

    if form.Email != "" {

      // Cleanup session state for controller.
      session.Clear()
      err := session.Save() // Remove flashes read, and save submit fields
      if err != nil {
        log.Debug(err.Error())
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }

      oauth2Config := app.FetchOAuth2Config(env, c)
      if oauth2Config == nil {
        log.Debug("Context missing oauth2 config")
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }
      idpClient := idp.NewIdpClientWithUserAccessToken(oauth2Config, &oauth2.Token{
        AccessToken: form.AccessToken,
      })
      emailChangeRequests := []idp.CreateHumansEmailChangeRequest{ {Id: form.Id, RedirectTo: config.GetString("meui.public.url") + config.GetString("meui.public.endpoints.profile") , Email:form.Email} }
      status, responses, err := idp.CreateHumansEmailChange(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.humans.emailchange"), emailChangeRequests)
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
        log.WithFields(logrus.Fields{ "status":status }).Debug("Create email change failed")
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }

      var challengeResponse idp.CreateHumansEmailChangeResponse
      reqStatus, reqErrors := bulky.Unmarshal(0, responses, &challengeResponse)

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

        log.WithFields(logrus.Fields{ "status":reqStatus, "errors":strings.Join(errors, ", ") }).Debug("Unmarshal CreateHumansEmailChangeResponse failed")
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }

      // Success
      redirectTo := challengeResponse.RedirectTo
      log.WithFields(logrus.Fields{"redirect_to": redirectTo}).Debug("Redirecting")
      c.Redirect(http.StatusFound, redirectTo)
      c.Abort()
      return
    }

    // Deny by default.
    log.WithFields(logrus.Fields{"redirect_to": submitUrl}).Debug("Redirecting")
    c.Redirect(http.StatusFound, submitUrl)
    c.Abort()
  }
  return gin.HandlerFunc(fn)
}