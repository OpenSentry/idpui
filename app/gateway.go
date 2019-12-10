package app

import (
  "errors"
  "fmt"
  "net/url"
  "crypto/rand"
  "encoding/base64"
  "github.com/gin-gonic/gin"
  "github.com/gin-contrib/sessions"
  "golang.org/x/oauth2"

  idp "github.com/opensentry/idp/client"
)

func IdpClientUsingAuthorizationCode(env *Environment, oauth2Delegator *oauth2.Config, c *gin.Context) (*idp.IdpClient) {
  accessToken := AccessToken(env, c)
  if accessToken != nil {
    return idp.NewIdpClientWithUserAccessToken(oauth2Delegator, accessToken)
  }
  return nil
}

func IdpClientUsingClientCredentials(env *Environment, c *gin.Context) (*idp.IdpClient) {
  return idp.NewIdpClient(env.IdpConfig)
}

func CreateRandomStringWithNumberOfBytes(numberOfBytes int) (string, error) {
  st := make([]byte, numberOfBytes)
  _, err := rand.Read(st)
  if err != nil {
    return "", err
  }
  return base64.StdEncoding.EncodeToString(st), nil
}

type ChallengeSession struct {
  State string

  //RedirectToSession string

  RedirectToOnSuccess string
  RedirectToOnFailure string
}

func StartChallengeSession(env *Environment, c *gin.Context, newChallengeSession ChallengeSession) (challengeSession *ChallengeSession, err error) {
  var state string

  if newChallengeSession.RedirectToOnSuccess == "" {
    return nil, errors.New("Missing redirect on success")
  }

  // Create random bytes that are based64 encoded to prevent character problems with the session store.
  state, err = CreateRandomStringWithNumberOfBytes(32);
  if err != nil {
    return nil, err
  }

  redirectToOnSuccessUrl, err := url.Parse(newChallengeSession.RedirectToOnSuccess)
  if err != nil {
    return nil, err
  }
  q := redirectToOnSuccessUrl.Query()
  q.Add("state", state)
  redirectToOnSuccessUrl.RawQuery = q.Encode()

  var _redirectToOnFailureUrl *url.URL
  if newChallengeSession.RedirectToOnFailure != "" {
    _redirectToOnFailureUrl, err = url.Parse(newChallengeSession.RedirectToOnFailure)
    if err != nil {
      return nil, err
    }
    q := _redirectToOnFailureUrl.Query()
    q.Add("state", state)
    _redirectToOnFailureUrl.RawQuery = q.Encode()
  }

  /*var _redirectToSessionUrl *url.URL
  if newChallengeSession.RedirectToSession != "" {
    _redirectToSessionUrl, err = url.Parse(newChallengeSession.RedirectToSession)
    if err != nil {
      return nil, err
    }
  }*/

  err = CreateSessionRedirect(env, c, state, redirectToOnSuccessUrl.String())
  if err != nil {
    return nil, err
  }

  var redirectToOnFailureUrl string
  if _redirectToOnFailureUrl != nil {
    redirectToOnFailureUrl = _redirectToOnFailureUrl.String()
  }

  ret := ChallengeSession{
    State: state,
    //RedirectToSession: redirectToSessionUrl.String(),
    RedirectToOnSuccess: redirectToOnSuccessUrl.String(),
    RedirectToOnFailure: redirectToOnFailureUrl,
  }
  return &ret, nil
}

func CreateSessionRedirect(env *Environment, c *gin.Context, state string, redirectTo string) (err error) {
  session := sessions.DefaultMany(c, env.Constants.SessionRedirectCsrfStoreKey)

  // Sanity check. Some did not cleaup properly
  v := session.Get(state)
  if v != nil {
    return errors.New("Session state exists")
  }

  session.Set(state, redirectTo)
  err = session.Save()
  if err != nil {
    return err
  }

  fmt.Printf("Session saved %s, %s", state, redirectTo)

  return nil
}

func ClearSessionRedirect(env *Environment, c *gin.Context, state string) {
  session := sessions.DefaultMany(c, env.Constants.SessionRedirectCsrfStoreKey)
  session.Delete(state)

  fmt.Printf("Session cleared %s", state)
}

func ValidateSessionState(env *Environment, c *gin.Context, state string) (valid bool) {
  session := sessions.DefaultMany(c, env.Constants.SessionRedirectCsrfStoreKey)
  v := session.Get(state)
  if v != nil { // Found redirect value stored in session, so is valid.
    return true
  }
  return false
}

func FetchSessionRedirect(env *Environment, c *gin.Context, state string) (redirectTo string, exists bool) {
  session := sessions.DefaultMany(c, env.Constants.SessionRedirectCsrfStoreKey)
  v := session.Get(state)
  if v != nil { // Found redirect value stored in session, so is valid.
    return redirectTo, true
  }
  return "", false
}

// Challenge sesssion

func RegisterChallengeSession(env *Environment, c *gin.Context, state string, challenge string) (err error) {
  session := sessions.DefaultMany(c, env.Constants.SessionChallengeStoreKey)

  // Sanity check. Some did not cleaup properly
  v := session.Get(state)
  if v != nil {
    return errors.New("Session challenge exists")
  }

  session.Set(state, challenge)
  err = session.Save()
  if err != nil {
    return err
  }

  fmt.Printf("Session challenge saved %s, %s", state, challenge)

  return nil
}
