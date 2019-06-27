package idpbe

import (
  "net/http"
  "bytes"
  "encoding/json"
  "io/ioutil"
  _ "fmt"
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

type UserInfoResponse struct {
  Sub       string      `json:"sub"`
}


func getDefaultHeaders() map[string][]string {
  return map[string][]string{
    "Content-Type": []string{"application/json"},
    "Accept": []string{"application/json"},
  }
}

func getDefaultHeadersWithAuthentication(accessToken string) map[string][]string {
  return map[string][]string{
    "Content-Type": []string{"application/json"},
    "Accept": []string{"application/json"},
    "Authorization": []string{"Bearer " + accessToken},
  }
}

// This probably needs to wrap a call to idpbe?
func FetchIdentityFromAccessToken(url string, accessToken string) (UserInfoResponse, error) {
  var response UserInfoResponse

  client := &http.Client{}

  request, _ := http.NewRequest("GET", url, nil)
  request.Header = getDefaultHeadersWithAuthentication(accessToken)

  rawResponse, err := client.Do(request)
  if err != nil {
    return response, err
  }

  responseData, err := ioutil.ReadAll(rawResponse.Body)
  if err != nil {
    return response, err
  }
  json.Unmarshal(responseData, &response)

  return response, nil
}

func FetchProfileForIdentity(url string, accessToken string, request IdentityRequest) (IdentityResponse, error) {
  var response IdentityResponse

  client := &http.Client{} // replace with oauth2 client calling idp-be instead and use client credentials flow.

  rawRequest, _ := http.NewRequest("GET", url, nil)
  rawRequest.Header = getDefaultHeadersWithAuthentication(accessToken)

  query := rawRequest.URL.Query()
  query.Add("id", request.Id)
  rawRequest.URL.RawQuery = query.Encode()

  rawResponse, err := client.Do(rawRequest)
  if err != nil {
    return response, err
  }

  responseData, _ := ioutil.ReadAll(rawResponse.Body)

  err = json.Unmarshal(responseData, &response)
  if err != nil {
    return response, err
  }

  return response, nil
}

func Authenticate(authenticateUrl string, client *http.Client, authenticateRequest AuthenticateRequest) (AuthenticateResponse, error) {
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

func Logout(logoutUrl string, client *http.Client, logoutRequest LogoutRequest) (LogoutResponse, error) {
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
