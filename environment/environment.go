package environment

import (
  "golang.org/x/oauth2"
  "golang.org/x/oauth2/clientcredentials"
  oidc "github.com/coreos/go-oidc"
)

const (
  SessionStoreKey string = "idpui"
  SessionStateKey string = "state"
  SessionTokenKey string = "token"
  SessionSubject string = "sub"
  SessionIdTokenKey string = "idtoken"
  RequestIdKey string = "RequestId"
  AccessTokenKey string = "access_token"
  IdTokenKey string = "id_token"
  LogKey string = "log"
)

type State struct {
  Provider *oidc.Provider
  IdpApiConfig *clientcredentials.Config
  AapApiConfig *clientcredentials.Config
  HydraConfig *oauth2.Config
}

type Route struct {
  URL string
  LogId string
}
