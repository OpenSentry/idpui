package idpbe

import (
  "golang-idp-fe/interfaces"
  // "golang.org/x/oauth2"
  "net/http"
  "bytes"
  "encoding/json"
  "io/ioutil"
)

func getDefaultHeaders() map[string][]string {
  return map[string][]string{
    "Content-Type": []string{"application/json"},
    "Accept": []string{"application/json"},
  }
}

func Authenticate(baseUrl string, authenticateRequest interfaces.AuthenticateRequest) (interfaces.AuthenticateResponse, error) {
  var authenticateResponse interfaces.AuthenticateResponse
  client := &http.Client{} // replace with oauth2 client calling idp-be instead and use client credentials flow.

  body, _ := json.Marshal(authenticateRequest)

  var data = bytes.NewBuffer(body)

  var url = baseUrl + "/v1/identities/authenticate"

  request, _ := http.NewRequest("POST", url, data)
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
