package environment

import (
  //"fmt"
  "golang.org/x/oauth2"
  "golang.org/x/oauth2/clientcredentials"
  oidc "github.com/coreos/go-oidc"
)

const (
  SessionStoreKey string = "idpfe"
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
  AppName string
  Provider *oidc.Provider
  IdpBeConfig *clientcredentials.Config
  CpBeConfig *clientcredentials.Config
  HydraConfig *oauth2.Config
}

type Route struct {
  URL string
  LogId string
}
