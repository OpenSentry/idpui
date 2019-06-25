package idpbe

import (
  "golang-idp-fe/interfaces"
  //"golang.org/x/oauth2"
  "net/http"
  "bytes"
  "encoding/json"
  "io/ioutil"
  _ "fmt"
)

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
func FetchIdentityFromAccessToken(url string, accessToken string) (interfaces.UserInfoResponse, error) {
  var response interfaces.UserInfoResponse

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

func FetchProfileForIdentity(url string, accessToken string, request interfaces.IdentityRequest) (interfaces.IdentityResponse, error) {
  var response interfaces.IdentityResponse

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

func Authenticate(authenticateUrl string, authenticateRequest interfaces.AuthenticateRequest) (interfaces.AuthenticateResponse, error) {
  var authenticateResponse interfaces.AuthenticateResponse

  client := &http.Client{} // replace with oauth2 client calling idp-be instead and use client credentials flow.

  body, _ := json.Marshal(authenticateRequest)

  var data = bytes.NewBuffer(body)

  request, _ := http.NewRequest("POST", authenticateUrl, data)
  request.Header = getDefaultHeaders()

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

func Logout(logoutUrl string, logoutRequest interfaces.LogoutRequest) (interfaces.LogoutResponse, error) {
  var logoutResponse interfaces.LogoutResponse

  client := &http.Client{} // replace with oauth2 client calling idp-be instead and use client credentials flow.

  body, _ := json.Marshal(logoutRequest)

  var data = bytes.NewBuffer(body)

  request, _ := http.NewRequest("POST", logoutUrl, data)
  request.Header = getDefaultHeaders()

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
