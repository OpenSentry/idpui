package config

import (
  "os"
)

/*
RedirectURL:  redirect url,
ClientID:     "GOOGLE_CLIENT_ID",
ClientSecret: "CLIENT_SECRET",
Scopes:       []string{"scope1", "scope2"},
Endpoint:     oauth2 endpoint,
*/

type HydraConfig struct {
  Url             string
  AdminUrl        string
  PublicUrl       string
  AuthenticateUrl string
  LogoutUrl       string
}

type IdpFeConfig struct {
  Url string
  PublicUrl string
  DefaultRedirectUrl string
  CsrfAuthKey string
  ClientId string
  ClientSecret string
}

type IdpBeConfig struct {
  Url string
  AuthenticateUrl string
  LogoutUrl string
}

var Hydra HydraConfig
var IdpFe IdpFeConfig
var IdpBe IdpBeConfig

func InitConfigurations() {
  Hydra.Url                   = getEnvStrict("HYDRA_URL")
  Hydra.AdminUrl              = getEnvStrict("HYDRA_ADMIN_URL")
  Hydra.PublicUrl             = getEnvStrict("HYDRA_PUBLIC_URL")
  Hydra.LogoutUrl             = Hydra.PublicUrl + "/oauth2/sessions/logout"
  Hydra.AuthenticateUrl       = Hydra.PublicUrl + "/oauth2/auth"

  IdpBe.Url                   = getEnvStrict("IDP_BACKEND_URL")
  IdpBe.AuthenticateUrl       = IdpBe.Url + "/v1/identities/authenticate"
  IdpBe.LogoutUrl             = IdpBe.Url + "/v1/identities/logout"

  IdpFe.Url                   = getEnvStrict("IDP_FRONTEND_URL")
  IdpFe.PublicUrl             = getEnvStrict("IDP_FRONTEND_PUBLIC_URL")
  IdpFe.DefaultRedirectUrl    = IdpFe.PublicUrl + "/welcome" // This needs to be part of the callback redirect uris of the client_id
  IdpFe.CsrfAuthKey           = getEnvStrict("IDP_FRONTEND_CSRF_AUTH_KEY") // 32 byte long auth key. When you change this user session will break.
  IdpFe.ClientId              = getEnvStrict("IDP_FRONTEND_OAUTH2_CLIENT_ID")
  IdpFe.ClientSecret          = getEnvStrict("IDP_FRONTEND_OAUTH2_CLIENT_SECRET")
}

func getEnv(name string) string {
  return os.Getenv(name)
}

func getEnvStrict(name string) string {
  r := getEnv(name)

  if r == "" {
    panic("Missing environment variable: " + name)
  }

  return r
}
