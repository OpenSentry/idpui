package credentials

import (
  "net/http"
  "bytes"
  "strings"
  "image/png"
  "encoding/base64"
  "time"
  "reflect"
  "gopkg.in/go-playground/validator.v9"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gin-contrib/sessions"
  "github.com/gorilla/csrf"
  "golang.org/x/oauth2"
  oidc "github.com/coreos/go-oidc"
  "github.com/pquerna/otp"
  "github.com/pquerna/otp/totp"
  idp "github.com/charmixer/idp/client"

  "github.com/charmixer/idpui/config"
  "github.com/charmixer/idpui/environment"
  "github.com/charmixer/idpui/utils"
  "github.com/charmixer/idpui/validators"
)


type totpForm struct {
  Totp string `form:"totp" binding:"required" validate:"required,notblank"`
  Secret string `form:"secret" binding:"required" validate:"required,notblank"`
}

func ShowTotp(env *environment.State) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowTotp",
    })

    // NOTE: Maybe session is not a good way to do this.
    // 1. The user access /me with a browser and the access token / id token is stored in a session as we cannot make the browser redirect with Authentication: Bearer <token>
    // 2. The user is using something that supplies the access token and id token directly in the headers. (aka. no need for the session)
    var idToken *oidc.IDToken
    session := sessions.Default(c)
    idToken = session.Get(environment.SessionIdTokenKey).(*oidc.IDToken)
    if idToken == nil {
      c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Missing id_token"})
      return
    }

    var accessToken *oauth2.Token
    accessToken = session.Get(environment.SessionTokenKey).(*oauth2.Token)
    idpClient := idp.NewIdpClientWithUserAccessToken(env.HydraConfig, accessToken)

    identityRequest := &idp.IdentitiesReadRequest{
      Id: idToken.Subject,
    }
    identity, err := idp.ReadIdentity(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.identities"), identityRequest)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "Identity not found"})
      return
    }

    millis := time.Now().UnixNano() / 1000000

    var key *otp.Key
    isStoredTotpKeyValid := false

    k := session.Get("totp.key")
    if k != nil {

      expTotp := session.Get("totp.exp")
      if expTotp != nil {
        exp := expTotp.(int64)

        if exp > millis {
          isStoredTotpKeyValid = true
        }
      }

    }

    if isStoredTotpKeyValid == true {

      key, err = otp.NewKeyFromURL(k.(string))
      if err != nil {
        log.Debug(err)
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }

    } else {

      totpOpts := totp.GenerateOpts{
        Issuer: config.GetString("idpui.public.url"),
        AccountName: identity.Id,
      }
      key, err = totp.Generate(totpOpts)
      if err != nil {
        log.WithFields(logrus.Fields{
          "totp.issuer": totpOpts.Issuer,
          "totp.accountname": totpOpts.AccountName,
        }).Debug(err)
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }

      session.Set("totp.key", key.String())
      session.Set("totp.exp", millis + (1000 * 60 * 15)) // 15 minutes // FIXME: Put into config
      err = session.Save()
      if err != nil {
        log.Debug(err.Error())
      }

    }

    // Convert TOTP key into a PNG
  	var buf bytes.Buffer
  	img, err := key.Image(200, 200)
  	if err != nil {
      log.Debug(err)
      c.AbortWithStatus(http.StatusInternalServerError)
      return
  	}
  	png.Encode(&buf, img)
    embedQrCode := base64.StdEncoding.EncodeToString(buf.Bytes())

    errors := session.Flashes("totp.errors")
    err = session.Save() // Remove flashes read, and save submit fields
    if err != nil {
      log.Debug(err.Error())
    }

    var errorTotp string

    if len(errors) > 0 {
      errorsMap := errors[0].(map[string][]string)
      for k, v := range errorsMap {

        if k == "totp" && len(v) > 0 {
          errorTotp = strings.Join(v, ", ")
        }

      }
    }

    c.HTML(http.StatusOK, "totp.html", gin.H{
      "title": "Two Factor Authentication",
      "links": []map[string]string{
        {"href": "/public/css/credentials.css"},
      },
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "provider": "Identity Provider",
      "provideraction": "Enable two-factor authentication for better security",
      "id": idToken.Subject,
      "issuer": key.Issuer(),
      "secret": key.Secret(),
      "qrcode": embedQrCode,
      "errorTotp": errorTotp,
    })
  }
  return gin.HandlerFunc(fn)
}
func SubmitTotp(env *environment.State) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "SubmitTotp",
    })

    var form totpForm
    err := c.Bind(&form)
    if err != nil {
      c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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

    // We need to validate that the user entered a correct otp form the authenticator app before enabling totp on the profile. Or we risk locking the user out of the system.
    // We should also generate a set of one time recovery codes and display to the user (simple generate a set of random codes and let the user print them)
    // see https://github.com/pquerna/otp, https://help.github.com/en/articles/configuring-two-factor-authentication-recovery-methods
    valid := totp.Validate(form.Totp, form.Secret)
    if len(errors) <= 0 && valid == false {
      errors["totp"] = append(errors["totp"], "Invalid")
    }

    if len(errors) > 0 {
      session.AddFlash(errors, "totp.errors")
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

    if valid == true {

      var idToken *oidc.IDToken
      idToken = session.Get(environment.SessionIdTokenKey).(*oidc.IDToken)
      if idToken == nil {
        c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "Missing id_token"})
        return
      }
      log.WithFields(logrus.Fields{"id": idToken.Subject}).Debug("TOTP verified")


      var accessToken *oauth2.Token
      accessToken = session.Get(environment.SessionTokenKey).(*oauth2.Token)
      idpClient := idp.NewIdpClientWithUserAccessToken(env.HydraConfig, accessToken)

      totpRequest := &idp.IdentitiesTotpRequest{
        Id: idToken.Subject,
        TotpRequired: true,
        TotpSecret: form.Secret,
      }
      updatedIdentity, err := idp.UpdateIdentityTotp(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.totp"), totpRequest);
      if err != nil {
        log.Debug(err.Error())
        c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
      }

      log.Debug(updatedIdentity)

      redirectTo := "/me"
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
