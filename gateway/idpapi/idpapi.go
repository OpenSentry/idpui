package idpapi

import (
  "errors"
  "net/http"
  "bytes"
  "encoding/json"
  "io/ioutil"
  "fmt"
  "golang.org/x/net/context"
  "golang.org/x/oauth2"
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
  Id            string          `json:"id" binding:"required"`
  Name          string          `json:"name,omitempty"`
  Email         string          `json:"email,omitempty"`
  Password      string          `json:"password,omitempty"`
}

type IdentityResponse struct {
  Id            string          `json:"id" binding:"required"`
  Name          string          `json:"name,omitempty"`
  Email         string          `json:"email,omitempty"`
  Password      string          `json:"password,omitempty" binding:"required"`
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
  Password        string
}

type IdpApiClient struct {
  *http.Client
}

func NewIdpApiClient(config *clientcredentials.Config) *IdpApiClient {
  ctx := context.Background()
  client := config.Client(ctx)
  return &IdpApiClient{client}
}

func NewIdpApiClientWithUserAccessToken(config *oauth2.Config, token *oauth2.Token) *IdpApiClient {
  ctx := context.Background()
  client := config.Client(ctx, token)
  return &IdpApiClient{client}
}

// config.AapApi.AuthorizationsUrl
func RevokeConsent(url string, client *IdpApiClient, revokeConsentRequest RevokeConsentRequest) (bool, error) {

  // FIXME: Call hydra directly. This should not be allowed! (idpui does not have hydra scope)
  // It should call aapapi instead. But for testing this was faster.
  u := "https://admin.oauth.localhost/oauth2/auth/sessions/consent?subject=" + revokeConsentRequest.Id
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

// config.IdpApi.IdentitiesUrl
func CreateProfile(identitiesUrl string, client *IdpApiClient, profile Profile) (Profile, error) {
  var identityResponse IdentityResponse
  var newProfile Profile

  identityRequest := IdentityRequest{
    Id: profile.Id,
    Name: profile.Name,
    Email: profile.Email,
    Password: profile.Password,
  }
  body, _ := json.Marshal(identityRequest)

  var data = bytes.NewBuffer(body)

  request, _ := http.NewRequest("POST", identitiesUrl, data)

  response, err := client.Do(request)
  if err != nil {
    return newProfile, err
  }

  responseData, _ := ioutil.ReadAll(response.Body)
  if response.StatusCode != 200 {
    fmt.Println(string(responseData))
    return newProfile, errors.New("Idpbe return non 200 error")
  }

  err = json.Unmarshal(responseData, &identityResponse)
  if err != nil {
    return newProfile, err
  }

  newProfile = Profile{
    Id: identityResponse.Id,
    Name: identityResponse.Name,
    Email: identityResponse.Email,
    Password: identityResponse.Password,
  }
  return newProfile, nil
}

// config.IdpApi.IdentitiesUrl
func FetchProfile(url string, client *IdpApiClient, identityRequest IdentityRequest) (Profile, error) {
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

// config.IdpApi.AuthenticateUrl
func Authenticate(authenticateUrl string, client *IdpApiClient, authenticateRequest AuthenticateRequest) (AuthenticateResponse, error) {
  var authenticateResponse AuthenticateResponse

  body, _ := json.Marshal(authenticateRequest)

  var data = bytes.NewBuffer(body)

  request, _ := http.NewRequest("POST", authenticateUrl, data)

  response, err := client.Do(request)
  if err != nil {
    return authenticateResponse, err
  }

  responseData, _ := ioutil.ReadAll(response.Body)

  if response.StatusCode != 200 {
    return authenticateResponse, errors.New(string(responseData))
  }

  err = json.Unmarshal(responseData, &authenticateResponse)
  if err != nil {
    return authenticateResponse, err
  }

  return authenticateResponse, nil
}

// config.IdpApi.LogoutUrl
func Logout(logoutUrl string, client *IdpApiClient, logoutRequest LogoutRequest) (LogoutResponse, error) {
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
