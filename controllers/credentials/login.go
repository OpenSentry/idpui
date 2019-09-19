package credentials

import (
  "net/url"
  "net/http"
  "crypto/rand"
  "encoding/base64"
  "strings"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"
  "github.com/gin-contrib/sessions"
  idp "github.com/charmixer/idp/client"

  "github.com/charmixer/idpui/config"
  "github.com/charmixer/idpui/environment"
)

type authenticationForm struct {
  Challenge string `form:"challenge" binding:"required"`
  Username string `form:"username" binding:"required"`
  Password string `form:"password" binding:"required"`
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
      initUrl, err := StartAuthenticationSession(env, c, log)
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

    idpClient := idp.NewIdpClient(env.IdpApiConfig)

    var authenticateRequest *idp.IdentitiesAuthenticateRequest
    otpChallenge := c.Query("otp_challenge")
    if otpChallenge != "" {
      authenticateRequest = &idp.IdentitiesAuthenticateRequest{
        Challenge: loginChallenge,
        OtpChallenge: otpChallenge,
      }
    } else {
      authenticateRequest = &idp.IdentitiesAuthenticateRequest{
        Challenge: loginChallenge,
      }
    }

    authenticateResponse, err := idp.AuthenticateIdentity(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.authenticate"), authenticateRequest)
    if err != nil {
      log.WithFields(logrus.Fields{
        "challenge": authenticateRequest.Challenge,
      }).Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    if authenticateResponse.Authenticated {
      log.WithFields(logrus.Fields{"authenticated": authenticateResponse.Authenticated, "redirect_to": authenticateResponse.RedirectTo}).Debug("Redirecting")
      c.Redirect(http.StatusFound, authenticateResponse.RedirectTo)
      c.Abort()
      return
    }

    session := sessions.Default(c)

    // Retain the values that was submittet, except passwords!
    username := session.Get("authenticate.username")

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

        if k == "errorUsername" && len(v) > 0 {
          errorUsername = strings.Join(v, ", ")
        }
        if k == "errorPassword" && len(v) > 0 {
          errorPassword = strings.Join(v, ", ")
        }

      }
    }

    c.HTML(200, "login.html", gin.H{
      "__links": []map[string]string{
        {"href": "/public/css/main.css"},
      },
      "__title": "Authenticate",
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "challenge": loginChallenge,
      "username": username,
      "errorUsername": errorUsername,
      "errorPassword": errorPassword,
      "loginUrl": config.GetString("idpui.public.login"),
      "recoverUrl": config.GetString("idpui.public.recover"),
      "registerUrl": config.GetString("idpui.public.register"),
    })
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

    // Save values if submit fails
    session.Set("authenticate.username", form.Username)
    err = session.Save()
    if err != nil {
      log.Debug(err.Error())
    }

    errors := make(map[string][]string)

    username := strings.TrimSpace(form.Username)
    if username == "" {
      errors["errorUsername"] = append(errors["errorUsername"], "Missing username")
    }

    password := form.Password
    if strings.TrimSpace(password) == "" {
      errors["errorPassword"] = append(errors["errorPassword"], "Missing password. Hint: Not allowed to be all whitespace")
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

    idpClient := idp.NewIdpClient(env.IdpApiConfig)

    identityRequest := &idp.IdentitiesReadRequest{
      Subject: username,
    }
    identityResponse, err := idp.ReadIdentity(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.identities"), identityRequest)
    if err != nil {
      log.WithFields(logrus.Fields{
        "subject": identityRequest.Subject,
        "challenge": form.Challenge,
      }).Debug(err.Error())
      c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      return
    }

    log.WithFields(logrus.Fields{"id": identityResponse.Id, "subject": identityResponse.Subject, "email": identityResponse.Email}).Debug("Found Identity")

    // Ask idp to authenticate the user
    authenticateRequest := &idp.IdentitiesAuthenticateRequest{
      Id: identityResponse.Id,
      Password: password,
      Challenge: form.Challenge,
    }
    authenticateResponse, err := idp.AuthenticateIdentity(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.authenticate"), authenticateRequest)
    if err != nil {
      log.WithFields(logrus.Fields{
        "id": authenticateRequest.Id,
        "challenge": authenticateRequest.Challenge,
      }).Debug(err.Error())
      c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      return
    }

    // User authenticated, redirect
    if authenticateResponse.Authenticated == true {

      // Cleanup session
      session.Delete("authenticate.username")
      session.Delete("authenticate.errors")

      err = session.Save()
      if err != nil {
        log.Debug(err.Error())
      }

      log.WithFields(logrus.Fields{
        "id": authenticateResponse.Id,
        "authenticated": authenticateResponse.Authenticated,
        "totp_required": authenticateResponse.TotpRequired,
        "redirect_to": authenticateResponse.RedirectTo,
      }).Debug("Redirecting")
      c.Redirect(http.StatusFound, authenticateResponse.RedirectTo)
      c.Abort()
      return
    }

    // Deny by default
    if authenticateResponse.IsPasswordInvalid == true {
      errors["errorUsername"] = append(errors["errorUsername"], "Invalid password")
    } else {
      errors["errorUsername"] = append(errors["errorUsername"], "Not found")
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

func CreateRandomStringWithNumberOfBytes(numberOfBytes int) (string, error) {
  st := make([]byte, numberOfBytes)
  _, err := rand.Read(st)
  if err != nil {
    return "", err
  }
  return base64.StdEncoding.EncodeToString(st), nil
}

func StartAuthenticationSession(env *environment.State, c *gin.Context, log *logrus.Entry) (*url.URL, error) {
  var state string
  var err error

  log = log.WithFields(logrus.Fields{
    "func": "StartAuthentication",
  })

  // Redirect to after successful authentication
  redirectTo := c.Request.RequestURI

  // Always generate a new authentication session state
  session := sessions.Default(c)

  // Create random bytes that are based64 encoded to prevent character problems with the session store.
  // The base 64 means that more than 64 bytes are stored! Which can cause "securecookie: the value is too long"
  // To prevent this we need to use a filesystem store instead of broser cookies.
  state, err = CreateRandomStringWithNumberOfBytes(32);
  if err != nil {
    log.Debug(err.Error())
    return nil, err
  }

  log.Debug(state)
  log.Debug(redirectTo)

  session.Set(environment.SessionStateKey, state)
  session.Set(state, redirectTo)
  err = session.Save()
  if err != nil {
    log.Debug(err.Error())
    return nil, err
  }

  logSession := log.WithFields(logrus.Fields{
    "redirect_to": redirectTo,
    "state": state,
  })
  logSession.Debug("Started session")
  authUrl := env.HydraConfig.AuthCodeURL(state)
  u, err := url.Parse(authUrl)
  return u, err
}
