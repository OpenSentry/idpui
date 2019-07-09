package idpbe

import (
  "net/http"
  "bytes"
  "encoding/json"
  "io/ioutil"
  "fmt"

  "golang.org/x/net/context"
  "golang.org/x/oauth2/clientcredentials"
)

type AuthenticateRequest struct {
  Id              string            `json:"id"`
  Password        string            `json:"password"`
  Challenge       string            `json:"challenge" binding:"required"`
}

type AuthenticateResponse struct {
  Id              string            `json:"id"`
  Authenticated   bool              `json:"authenticated"`
  RedirectTo      string            `json:"redirect_to,omitempty"`
}

type LogoutRequest struct {
  Challenge       string            `json:"challenge" binding:"required"`
}

type LogoutResponse struct {
  RedirectTo      string            `json:"redirect_to" binding:"required"`
}

type IdentityRequest struct {
  Id              string            `json:"id"`
}

type IdentityResponse struct {
  Id            string          `json:"id"`
  Name          string          `json:"name"`
  Email         string          `json:"email"`
}

type RevokeConsentRequest struct {
  Id string `json:"id"`
}

type UserInfoResponse struct {
  Sub       string      `json:"sub"`
}

type Profile struct {
  Id              string
  Name            string
  Email           string
}

type IdpBeClient struct {
  *http.Client
}

func NewIdpBeClient(config *clientcredentials.Config) *IdpBeClient {
  ctx := context.Background()
  client := config.Client(ctx)
  return &IdpBeClient{client}
}

func RevokeConsent(url string, client *IdpBeClient, revokeConsentRequest RevokeConsentRequest) (bool, error) {

  // FIXME: Call hydra directly. This should not be allowed! (idpfe does not have hydra scope)
  // It should call cpbe instead. But for testing this was faster.
  u := "https://hydra:4445/oauth2/auth/sessions/consent?subject=" + revokeConsentRequest.Id
  consentRequest, err := http.NewRequest("DELETE", u, nil)
  if err != nil {
    return false, err
  }

  rawResponse, err := client.Do(consentRequest)
  if err != nil {
    return false, err
  }

  responseData, err := ioutil.ReadAll(rawResponse.Body)
  if err != nil {
    return false, err
  }

  fmt.Println(responseData)

  return true, nil
}

func FetchProfile(url string, client *IdpBeClient, identityRequest IdentityRequest) (Profile, error) {
  var profile Profile
  var identityResponse IdentityResponse
  var userInfoResponse UserInfoResponse

  id := identityRequest.Id
  if id == "" {
    // Ask hydra for user from access token in client.
    userInfoRequest, err := http.NewRequest("GET", url, nil)
    if err != nil {
      return profile, err
    }

    rawResponse, err := client.Do(userInfoRequest)
    if err != nil {
      return profile, err
    }

    responseData, err := ioutil.ReadAll(rawResponse.Body)
    if err != nil {
      return profile, err
    }

    json.Unmarshal(responseData, &userInfoResponse)
    id = userInfoResponse.Sub
  }

  rawRequest, err := http.NewRequest("GET", url, nil)
  if err != nil {
    return profile, err
  }

  query := rawRequest.URL.Query()
  query.Add("id", id)
  rawRequest.URL.RawQuery = query.Encode()

  rawResponse, err := client.Do(rawRequest)
  if err != nil {
    return profile, err
  }

  responseData, err := ioutil.ReadAll(rawResponse.Body)
  if err != nil {
    return profile, err
  }

  err = json.Unmarshal(responseData, &identityResponse)
  if err != nil {
    return profile, err
  }

  profile = Profile{
    Id: identityResponse.Id,
    Name: identityResponse.Name,
    Email: identityResponse.Email,
  }
  return profile, nil
}

func Authenticate(authenticateUrl string, client *IdpBeClient, authenticateRequest AuthenticateRequest) (AuthenticateResponse, error) {
  var authenticateResponse AuthenticateResponse

  body, _ := json.Marshal(authenticateRequest)

  var data = bytes.NewBuffer(body)

  request, _ := http.NewRequest("POST", authenticateUrl, data)

  response, err := client.Do(request)
  if err != nil {
    return authenticateResponse, err
  }

  responseData, _ := ioutil.ReadAll(response.Body)

  err = json.Unmarshal(responseData, &authenticateResponse)
  if err != nil {
    return authenticateResponse, err
  }

  return authenticateResponse, nil
}

func Logout(logoutUrl string, client *IdpBeClient, logoutRequest LogoutRequest) (LogoutResponse, error) {
  var logoutResponse LogoutResponse

  body, _ := json.Marshal(logoutRequest)

  var data = bytes.NewBuffer(body)

  request, _ := http.NewRequest("POST", logoutUrl, data)

  response, err := client.Do(request)
  if err != nil {
    return logoutResponse, err
  }

  responseData, _ := ioutil.ReadAll(response.Body)

  err = json.Unmarshal(responseData, &logoutResponse)
  if err != nil {
    return logoutResponse, err
  }

  return logoutResponse, nil
}
