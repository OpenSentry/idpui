package environment

import (
  "golang.org/x/oauth2"
  "golang.org/x/oauth2/clientcredentials"
  oidc "github.com/coreos/go-oidc"
)

type SessionKeys struct {
  SessionAppStore string
}

const (
  SessionStateKey string = "state"
  SessionTokenKey string = "token"
  SessionIdTokenKey string = "idtoken"
  RequestIdKey string = "RequestId"
  AccessTokenKey string = "access_token"
  IdTokenKey string = "id_token"
  LogKey string = "log"
)

type State struct {
  SessionKeys *SessionKeys
  Provider *oidc.Provider
  IdpApiConfig *clientcredentials.Config
  AapApiConfig *clientcredentials.Config
  HydraConfig *oauth2.Config
}
