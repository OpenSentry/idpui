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
  AuthenticateUrl string
  TokenUrl        string
  UserInfoUrl     string
  PublicUrl             string
  PublicAuthenticateUrl string
  PublicTokenUrl        string
  PublicLogoutUrl       string
  PublicUserInfoUrl     string
}

type IdpFeConfig struct {
  Url string
  PublicUrl string
  DefaultRedirectUrl string
  CsrfAuthKey string
  ClientId string
  ClientSecret string
  RequiredScopes []string
}

type IdpBeConfig struct {
  Url string
  IdentitiesUrl string
  AuthenticateUrl string
  LogoutUrl string
}

var Hydra HydraConfig
var IdpFe IdpFeConfig
var IdpBe IdpBeConfig

func InitConfigurations() {
  Hydra.Url                   = getEnvStrict("HYDRA_URL")
  Hydra.AdminUrl              = getEnvStrict("HYDRA_ADMIN_URL")
  Hydra.AuthenticateUrl       = Hydra.Url + "/oauth2/auth"
  Hydra.TokenUrl              = Hydra.Url + "/oauth2/token"
  Hydra.UserInfoUrl           = Hydra.Url + "/userinfo"

  Hydra.PublicUrl             = getEnvStrict("HYDRA_PUBLIC_URL")
  Hydra.PublicLogoutUrl       = Hydra.PublicUrl + "/oauth2/sessions/logout"
  Hydra.PublicAuthenticateUrl = Hydra.PublicUrl + "/oauth2/auth"
  Hydra.PublicTokenUrl        = Hydra.PublicUrl + "/oauth2/token"
  Hydra.PublicUserInfoUrl     = Hydra.PublicUrl + "/userinfo"

  IdpBe.Url                   = getEnvStrict("IDP_BACKEND_URL")
  IdpBe.IdentitiesUrl         = IdpBe.Url + "/identities"
  IdpBe.AuthenticateUrl       = IdpBe.IdentitiesUrl + "/authenticate"
  IdpBe.LogoutUrl             = IdpBe.IdentitiesUrl + "/logout"

  IdpFe.Url                   = getEnvStrict("IDP_FRONTEND_URL")
  IdpFe.PublicUrl             = getEnvStrict("IDP_FRONTEND_PUBLIC_URL")
  IdpFe.DefaultRedirectUrl    = IdpFe.PublicUrl + "/me" // This needs to be part of the callback redirect uris of the client_id
  IdpFe.CsrfAuthKey           = getEnvStrict("IDP_FRONTEND_CSRF_AUTH_KEY") // 32 byte long auth key. When you change this user session will break.
  IdpFe.ClientId              = getEnvStrict("IDP_FRONTEND_OAUTH2_CLIENT_ID")
  IdpFe.ClientSecret          = getEnvStrict("IDP_FRONTEND_OAUTH2_CLIENT_SECRET")
  IdpFe.RequiredScopes        = []string{"openid"}

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
