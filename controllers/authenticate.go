package controllers

import (
  "fmt"
  "net/url"
  "net/http"
  "crypto/rand"
  "encoding/base64"

  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"
  "github.com/gin-contrib/sessions"

  "golang-idp-fe/config"
  "golang-idp-fe/environment"
  "golang-idp-fe/gateway/idpbe"
)

type authenticationForm struct {
    Challenge string `form:"challenge"`
    Username string `form:"username"`
    Password string `form:"password"`
}

func ShowAuthentication(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {
    environment.DebugLog(route.LogId, "ShowAuthentication", "", c.MustGet(environment.RequestIdKey).(string))

    // Look for flash session of a registering new profile event
    session := sessions.Default(c)
    v := session.Get(environment.SessionSubject)
    fmt.Println("CHECKING FOR SESSION SUBJECT")
    fmt.Println(v)
    if v != nil {
      fmt.Println("DELETING SUBJECT AGAIN")
      session.Delete(environment.SessionSubject)
      session.Save()
    }

    loginChallenge := c.Query("login_challenge")
    if loginChallenge == "" {
      // User is visiting login page as the first part of the process, probably meaning. Want to view profile or change it.
      // Idp-Fe should ask hydra for a challenge to login
      initUrl, err := StartAuthentication(env, c, route)
      if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        c.Abort()
        return
      }
      c.Redirect(http.StatusFound, initUrl.String())
      c.Abort()
      return
    }

    idpbeClient := idpbe.NewIdpBeClient(env.IdpBeConfig)

    var authenticateRequest = idpbe.AuthenticateRequest{
      Challenge: loginChallenge,
    }
    authenticateResponse, err := idpbe.Authenticate(config.IdpBe.AuthenticateUrl, idpbeClient, authenticateRequest)
    if err != nil {
      c.JSON(400, gin.H{"error": err.Error()})
      c.Abort()
      return
    }
    if authenticateResponse.Authenticated {
      c.Redirect(302, authenticateResponse.RedirectTo)
      c.Abort()
      return
    }
    loginError := c.Query("login_error")
    c.HTML(200, "authenticate.html", gin.H{
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "challenge": loginChallenge,
      "login_error": loginError,
    })
  }
  return gin.HandlerFunc(fn)
}

func SubmitAuthentication(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {
    environment.DebugLog(route.LogId, "SubmitAuthentication", "", c.MustGet(environment.RequestIdKey).(string))

    var form authenticationForm
    err := c.Bind(&form)
    if err != nil {
      // Do better error handling in the application.
      c.JSON(400, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    if form.Username == "" {
      // FIXME: session flash missing username
    }
    if form.Password == "" {
      // FIXME: session flash missing username
    }

    idpbeClient := idpbe.NewIdpBeClient(env.IdpBeConfig)

    // Ask idp-be to authenticate the user
    var authenticateRequest = idpbe.AuthenticateRequest{
      Id: form.Username,
      Password: form.Password,
      Challenge: form.Challenge,
    }
    authenticateResponse, err := idpbe.Authenticate(config.IdpBe.AuthenticateUrl, idpbeClient, authenticateRequest)
    if err != nil {
      c.JSON(400, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    // User authenticated, redirect
    if authenticateResponse.Authenticated {
      c.Redirect(302, authenticateResponse.RedirectTo)
      c.Abort()
      return
    }

    // Deny by default
    // Failed authentication, retry login challenge.
    retryLoginUrl := "/?login_challenge=" + form.Challenge + "&login_error=Authentication Failure";
    retryUrl, err := url.Parse(retryLoginUrl)
    if err != nil {
      c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
      c.Abort()
      return
    }
    c.Redirect(302, retryUrl.String())
    c.Abort()
  }
  return gin.HandlerFunc(fn)
}

func StartAuthentication(env *environment.State, c *gin.Context, route environment.Route) (*url.URL, error) {
  var state string
  session := sessions.Default(c)
  v := session.Get(environment.SessionStateKey)
  if v == nil {
    // No state in session found, so calculate one.
    st := make([]byte, 64) // 64 bytes
    _, err := rand.Read(st)
    if err != nil {
      return &url.URL{}, err
    }
    state = base64.StdEncoding.EncodeToString(st)
    session.Set(environment.SessionStateKey, state)
		err = session.Save()
    if err != nil {
      environment.DebugLog(route.LogId, "StartAuthentication", err.Error(), c.MustGet(environment.RequestIdKey).(string))
    }
    environment.DebugLog(route.LogId, "StartAuthentication", "Saved session "+environment.SessionStateKey+": " + state, c.MustGet(environment.RequestIdKey).(string))
  } else {
    state = v.(string)
  }

  environment.DebugLog(route.LogId, "StartAuthentication", "Using "+environment.SessionStateKey+" param: " + state, c.MustGet(environment.RequestIdKey).(string))
  authUrl := env.HydraConfig.AuthCodeURL(state) //idpfeHydraPublic.AuthCodeURL(state)
  u, err := url.Parse(authUrl)
  return u, err
}
