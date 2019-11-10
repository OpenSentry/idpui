package credentials

import (
  "net/url"
  "net/http"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"
  "github.com/gin-contrib/sessions"
  //"golang.org/x/oauth2"


  idp "github.com/charmixer/idp/client"

  "github.com/charmixer/idpui/app"
  "github.com/charmixer/idpui/config"

  bulky "github.com/charmixer/bulky/client"
)

type logoutForm struct {
  Challenge string `form:"challenge" binding:"required" validate:"required,notblank"`
}

func ShowLogout(env *app.Environment) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(env.Constants.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowLogout",
    })

    idpClient := app.IdpClientUsingClientCredentials(env, c)

    logoutChallenge := c.Query("logout_challenge")
    if logoutChallenge == "" {

      idTokenHint := app.IdTokenHint(env, c)
      if idTokenHint == "" {
        log.Debug("Missing id_token_hint")
        c.AbortWithStatus(http.StatusUnauthorized)
        return
      }

      state, err := app.CreateRandomStringWithNumberOfBytes(12);
      if err != nil {
        log.Debug(err.Error())
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }

      var postLogoutRedirectUrl *url.URL
      onLogoutRedirectTo := config.GetString("idpui.public.url") + config.GetString("idpui.public.endpoints.seeyoulater")
      if onLogoutRedirectTo != "" {

        postLogoutRedirectUrl, err = url.Parse(onLogoutRedirectTo)
        if err != nil {
          log.Debug(err.Error())
          c.AbortWithStatus(http.StatusInternalServerError)
          return
        }

      }

      logoutRequest := []idp.CreateHumansLogoutRequest{ { IdToken:idTokenHint, RedirectTo:postLogoutRedirectUrl.String(), State:state } }
      status, responses, err := idp.CreateHumansLogout(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.humans.logout"), logoutRequest)
      if err != nil {
        log.Debug(err.Error())
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }

      if status == 200 {

        var logoutResponse idp.CreateHumansLogoutResponse
        status, _ = bulky.Unmarshal(0, responses, &logoutResponse)
        if status == 200 {

          session := sessions.DefaultMany(c, env.Constants.SessionStoreKey)
          session.Set(env.Constants.SessionLogoutStateKey, state)
          err = session.Save()
          if err != nil {
            log.Debug(err.Error())
            c.AbortWithStatus(http.StatusInternalServerError)
            return
          }

          log.WithFields(logrus.Fields{ "redirect_to":logoutResponse.RedirectTo }).Debug("Redirecting")
          c.Redirect(http.StatusFound, logoutResponse.RedirectTo)
          c.Abort()
          return
        }

      }

      // Deny by default
      c.AbortWithStatus(http.StatusNotFound)
      return
    }

    challenge, err := readLogoutChallenge(idpClient, logoutChallenge)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    if challenge != nil {

      // Challenge exists, render so we can accept it.
      log.Debug(challenge)

      c.HTML(200, "logout.html", gin.H{
        "links": []map[string]string{
          {"href": "/public/css/credentials.css"},
        },
        "title": "Logout",
        csrf.TemplateTag: csrf.TemplateField(c.Request),
        "provider": "Identity Provider",
        "provideraction": "Logout of the system",
        "challenge": logoutChallenge,
        "logoutUrl": config.GetString("idpui.public.endpoints.logout"),
      })
      return
    }

    // Deny by default
    log.WithFields(logrus.Fields{ "challenge":logoutChallenge }).Debug("Not Found")
    c.AbortWithStatus(http.StatusNotFound)
  }
  return gin.HandlerFunc(fn)
}

func SubmitLogout(env *app.Environment) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(env.Constants.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "SubmitLogout",
    })

    var form logoutForm
    err := c.Bind(&form)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      return
    }

    idpClient := app.IdpClientUsingClientCredentials(env, c)
    //idpClient := app.IdpClientUsingAuthorizationCode(env, oauth2Config, c)

    challenge, err := readLogoutChallenge(idpClient, form.Challenge)
    if err != nil {
      log.Debug(err.Error())
      c.AbortWithStatus(http.StatusInternalServerError)
      return
    }

    if challenge != nil {

      // Accept the logout
      logoutRequest := []idp.UpdateHumansLogoutAcceptRequest{ { Challenge:form.Challenge } }
      status, responses, err := idp.UpdateHumansLogoutAccept(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.humans.logout"), logoutRequest)
      if err != nil {
        log.Debug(err.Error())
        c.AbortWithStatus(http.StatusInternalServerError)
        return
      }

      if status == 200 {

        var acceptResponse idp.UpdateHumansLogoutAcceptResponse
        status, _ = bulky.Unmarshal(0, responses, &acceptResponse)
        if status == 200 {

          session := sessions.DefaultMany(c, env.Constants.SessionStoreKey)
          session.Delete(env.Constants.SessionLogoutStateKey)
          err = session.Save()
          if err != nil {
            log.Debug(err.Error())
            c.AbortWithStatus(http.StatusInternalServerError)
            return
          }

          log.WithFields(logrus.Fields{ "redirect_to":acceptResponse.RedirectTo }).Debug("Redirecting")
          c.Redirect(http.StatusFound, acceptResponse.RedirectTo)
          c.Abort()
          return
        }

      }

    }

    // Deny by default
    log.WithFields(logrus.Fields{ "challenge":form.Challenge }).Debug("Not Found")
    c.AbortWithStatus(http.StatusNotFound)
  }
  return gin.HandlerFunc(fn)
}

type LogoutChallenge struct {
  Challenge string
  State string
  RedirectTo string
}

func readLogoutChallenge(idpClient *idp.IdpClient, challenge string) (lc *LogoutChallenge, err error) {
  logoutRequest := []idp.ReadHumansLogoutRequest{ { Challenge:challenge } }
  status, responses, err := idp.ReadHumansLogout(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.humans.logout"), logoutRequest)
  if err != nil {
    return nil, err
  }

  if status == 200 {

    var logoutResponse idp.ReadHumansLogoutResponse
    status, _ = bulky.Unmarshal(0, responses, &logoutResponse)
    if status == 200 {

      u, err := url.Parse(logoutResponse.RequestUrl)
      if err != nil {
        return nil, err
      }

      q := u.Query()
      state := q.Get("state")
      challenge := q.Get("challenge")

      lc := &LogoutChallenge{
        Challenge: challenge,
        State: state,
        RedirectTo: logoutResponse.RequestUrl,
      }
      return lc, nil
    }

  }

  return nil, nil
}