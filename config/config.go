package config

import (
  "os"
)

type SelfConfig struct {
  Port          string
}

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
  SessionAuthKey []byte
  Url string
  PublicUrl string
  PublicCallbackUrl string
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

type CpBeConfig struct {
  Url string
  AuthorizationsUrl string
  AuthorizationsAuthorizeUrl string
  AuthorizationsRejectUrl string
}

var Hydra HydraConfig
var IdpFe IdpFeConfig
var IdpBe IdpBeConfig
var CpBe CpBeConfig
var Self SelfConfig

func InitConfigurations() {
  Self.Port                   = getEnvStrict("PORT")

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

  IdpFe.SessionAuthKey        = []byte(getEnvStrict("IDP_FRONTEND_SESSION_AUTH_KEY"))
  IdpFe.Url                   = getEnvStrict("IDP_FRONTEND_URL")
  IdpFe.PublicUrl             = getEnvStrict("IDP_FRONTEND_PUBLIC_URL")
  IdpFe.PublicCallbackUrl     = IdpFe.PublicUrl + "/callback" // This needs to be part of the callback redirect uris of the client_id
  IdpFe.DefaultRedirectUrl    = IdpFe.PublicUrl + "/me"
  IdpFe.CsrfAuthKey           = getEnvStrict("IDP_FRONTEND_CSRF_AUTH_KEY") // 32 byte long auth key. When you change this user session will break.
  IdpFe.ClientId              = getEnvStrict("IDP_FRONTEND_OAUTH2_CLIENT_ID")
  IdpFe.ClientSecret          = getEnvStrict("IDP_FRONTEND_OAUTH2_CLIENT_SECRET")
  IdpFe.RequiredScopes        = []string{"openid", "idpbe.authenticate"}

  CpBe.Url                         = getEnvStrict("CP_BACKEND_URL")
  CpBe.AuthorizationsUrl           = CpBe.Url + "/authorizations"
  CpBe.AuthorizationsAuthorizeUrl  = CpBe.AuthorizationsUrl + "/authorize"
  CpBe.AuthorizationsRejectUrl     = CpBe.AuthorizationsUrl + "/reject"

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
