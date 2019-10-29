package app

import (
  "net/url"
  "crypto/rand"
  "encoding/base64"
  "github.com/gin-gonic/gin"
  "github.com/gin-contrib/sessions"

  idp "github.com/charmixer/idp/client"
  aap "github.com/charmixer/aap/client"
  "github.com/charmixer/idpui/config"

  bulky "github.com/charmixer/bulky/client"
)

func IdpClientUsingAuthorizationCode(env *Environment, c *gin.Context) (*idp.IdpClient) {
  accessToken := AccessToken(env, c)
  if accessToken != nil {
    return idp.NewIdpClientWithUserAccessToken(env.OAuth2Delegator, accessToken)
  }
  return nil
}

func IdpClientUsingClientCredentials(env *Environment, c *gin.Context) (*idp.IdpClient) {
  return idp.NewIdpClient(env.IdpConfig)
}

func AapClientUsingClientCredentials(env *Environment, c *gin.Context) (*aap.AapClient) {
  return aap.NewAapClient(env.AapConfig)
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
  SessionStateKey string
  SessionRedirectTo string
  OnVerifiedRedirectTo string
  State string
}

func StartChallengeSession(c *gin.Context, newChallengeSession ChallengeSession) (challengeSession *ChallengeSession, err error) {
  var state string

  // Create random bytes that are based64 encoded to prevent character problems with the session store.
  state, err = CreateRandomStringWithNumberOfBytes(32);
  if err != nil {
    return nil, err
  }

  urlRedirectToOnVerified, err := url.Parse(newChallengeSession.OnVerifiedRedirectTo)
  if err != nil {
    return nil, err
  }
  q := urlRedirectToOnVerified.Query()
  q.Add("state", state)
  urlRedirectToOnVerified.RawQuery = q.Encode()

  session := sessions.Default(c)
  session.Set(newChallengeSession.SessionStateKey, state)
  if newChallengeSession.SessionRedirectTo != "" {
    urlSessionRedirectTo, err := url.Parse(newChallengeSession.SessionRedirectTo)
    if err != nil {
      return nil, err
    }
    session.Set(state, urlSessionRedirectTo.String())
  }
  err = session.Save()
  if err != nil {
    return nil, err
  }
  ret := ChallengeSession{
    SessionStateKey: newChallengeSession.SessionStateKey,
    SessionRedirectTo: newChallengeSession.SessionRedirectTo,
    OnVerifiedRedirectTo: urlRedirectToOnVerified.String(),
    State: state,
  }
  return &ret, nil
}

func FetchInvite(idpClient *idp.IdpClient, id string) (*idp.Invite, error) {

  inviteRequest := []idp.ReadInvitesRequest{ {Id: id} }
  status, responses, err := idp.ReadInvites(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.invites.collection"), inviteRequest)
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
  }

  return nil, nil
}