package controllers

import (
  "net/http"
  "bytes"
  "strings"
  "image/png"
  "encoding/base64"

  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gin-contrib/sessions"
  "github.com/gorilla/csrf"
  "golang.org/x/oauth2"
  oidc "github.com/coreos/go-oidc"
  "github.com/pquerna/otp/totp"
  idp "github.com/charmixer/idp/client"
  "github.com/charmixer/idp/identities"

  "github.com/charmixer/idpui/config"
  "github.com/charmixer/idpui/environment"
)

type totpForm struct {
  Otp string `form:"otp"`
  Secret string `form:"secret"`
}

func ShowTotp(env *environment.State, route environment.Route) gin.HandlerFunc {
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
      c.HTML(http.StatusNotFound, "totp.html", gin.H{"error": "Identity not found"})
      c.Abort()
      return
    }

    var accessToken *oauth2.Token
    accessToken = session.Get(environment.SessionTokenKey).(*oauth2.Token)
    idpClient := idp.NewIdpApiClientWithUserAccessToken(env.HydraConfig, accessToken)

    // Look up profile information for user.
    identityRequest := identities.IdentitiesRequest{
      Id: idToken.Subject,
    }
    profile, err := idp.FetchIdentity(config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.identities"), idpClient, identityRequest)
    if err != nil {
      c.HTML(http.StatusNotFound, "totp.html", gin.H{"error": "Identity not found"})
      c.Abort()
      return
    }

    totpOpts := totp.GenerateOpts{
      Issuer: config.GetString("idpui.public.url"),
      AccountName: profile.Id,
    }
    key, err := totp.Generate(totpOpts)
    if err != nil {
      log.WithFields(logrus.Fields{
        "totp.issuer": totpOpts.Issuer,
        "totp.accountname": totpOpts.AccountName,
      }).Debug(err)
      c.HTML(http.StatusInternalServerError, "totp.html", gin.H{"error": "Failed to generate TOTP code"})
      c.Abort()
      return
    }

    // Convert TOTP key into a PNG
  	var buf bytes.Buffer
  	img, err := key.Image(200, 200)
  	if err != nil {
      log.Debug(err)
      c.HTML(http.StatusInternalServerError, "totp.html", gin.H{"error": "Failed to generate QR code PNG"})
      c.Abort()
      return
  	}
  	png.Encode(&buf, img)
    embedQrCode := base64.StdEncoding.EncodeToString(buf.Bytes())

    c.HTML(http.StatusOK, "totp.html", gin.H{
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "__title": "Two Factor Authentication",
      "user": idToken.Subject,
      "name": profile.Name,
      "email": profile.Email,
      "issuer": key.Issuer(),
      "secret": key.Secret(),
      "qrcode": embedQrCode,
    })
  }
  return gin.HandlerFunc(fn)
}
func SubmitTotp(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "Submit2Fa",
    })

    var form totpForm
    err := c.Bind(&form)
    if err != nil {
      // Do better error handling in the application.
      c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    session := sessions.Default(c)

    errors := make(map[string][]string)

    otp := strings.TrimSpace(form.Otp)
    if otp == "" {
      errors["errorOtp"] = append(errors["errorOtp"], "Missing otp")
    }

    if len(errors) > 0 {
      session.AddFlash(errors, "totp.errors")
      err = session.Save()
      if err != nil {
        log.Debug(err.Error())
      }
      log.WithFields(logrus.Fields{"redirect_to": route.URL}).Debug("Redirecting")
      c.Redirect(http.StatusFound, route.URL)
      c.Abort();
      return
    }

    // We need to validate that the user entered a correct otp form the authenticator app before enabling totp on the profile. Or we risk locking the user out of the system.
    // We should also generate a set of one time recovery codes and display to the user (simple generate a set of random codes and let the user print them)
    // see https://github.com/pquerna/otp, https://help.github.com/en/articles/configuring-two-factor-authentication-recovery-methods
  	valid := totp.Validate(form.Otp, form.Secret)
    if valid == true {

      var idToken *oidc.IDToken
      idToken = session.Get(environment.SessionIdTokenKey).(*oidc.IDToken)
      if idToken == nil {
        c.HTML(http.StatusNotFound, "totp.html", gin.H{"error": "Identity not found"})
        c.Abort()
        return
      }

      var accessToken *oauth2.Token
      accessToken = session.Get(environment.SessionTokenKey).(*oauth2.Token)
      idpClient := idp.NewIdpApiClientWithUserAccessToken(env.HydraConfig, accessToken)

      log.WithFields(logrus.Fields{
        "id": idToken.Subject,
        /* DO NOT LOG THIS IS LIKE PASSWORDS
        "otp": form.Otp,
        "secret": form.Secret,
        */
      }).Debug("Otp verified")

      var totpRequest = identities.TotpRequest{
        Id: idToken.Subject,
        TotpRequired: true,
        TotpSecret: form.Secret,
      }
      profile, err := idp.UpdateTotp(config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.totp"), idpClient, totpRequest);
      if err != nil {
        log.Debug(err.Error())
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        c.Abort()
        return
      }

      log.Debug(profile)

      log.WithFields(logrus.Fields{"redirect_to": "/me"}).Debug("Redirecting")
      c.Redirect(http.StatusFound, "/me")
      return
    }

    // Deny by default. Failed to fill in the form correctly.
    c.Redirect(http.StatusFound, route.URL)
    c.Abort()
  }
  return gin.HandlerFunc(fn)
}
