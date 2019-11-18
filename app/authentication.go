package app

import (
  //"fmt"
  "strings"
  "errors"
  "net/http"
  "net/url"
  "github.com/gin-gonic/gin"
  "golang.org/x/oauth2"

  "github.com/charmixer/idpui/config"
)

// # Authentication and Authorization
// ## QTNA - Questions that need answering before granting access to a protected resource
// 1. Is the user or client authenticated? Answered by the process of obtaining an access token.
// 2. Is the access token expired?
// 3. Is the access token granted the required scopes?
// 4. Is the user or client giving the grants in the access token authorized to operate the scopes granted?
// 5. Is the access token revoked?

func createAuthorizationCodeExchangeUrl(req *http.Request) (exchangeUrl string, err error) {
  baseUrl := config.GetString("idpui.public.url")

  // allowedRedirectUris := []string{
  //   baseUrl + config.GetString("idpui.public.endpoints.login"),
  //   baseUrl + config.GetString("idpui.public.endpoints.password"),
  //   baseUrl + config.GetString("idpui.public.endpoints.emailchangeconfirm"), // FIXME: This needs the email_challenge param to be present from the email_change controller to be present or it fails.
  //   baseUrl + config.GetString("idpui.public.endpoints.totp"),
  //   baseUrl + config.GetString("idpui.public.endpoints.delete"),
  // }
  requestedURL, err := url.Parse(req.RequestURI)
  if err != nil {
    return "", err
  }

  // Clean query params
  q := url.Values{}
  requestedURL.RawQuery = q.Encode()

  if requestedURL.Host == "" {
    exchangeUrl = baseUrl
  }
  exchangeUrl = exchangeUrl + requestedURL.String()

  return exchangeUrl, nil
}

func createPostRedirectUri(requestedUrl string) (redirectTo string, err error) {

  // Do not allowed landing on any urls that start the authentication process as it can create infinite loops.
  /*
    WITH OR WITHOUT BASE URL THESE WILL make infinite redirects
    config.GetString("idpui.public.url") + config.GetString("idpui.public.endpoints.login")

    config.GetString("idpui.public.url") + config.GetString("idpui.public.endpoints.password"),
    config.GetString("idpui.public.url") + config.GetString("idpui.public.endpoints.emailchange"),
    config.GetString("idpui.public.url") + config.GetString("idpui.public.endpoints.emailchangeconfirm"), // FIXME: This needs the email_challenge param to be present from the email_change controller to be present or it fails.
    config.GetString("idpui.public.url") + config.GetString("idpui.public.endpoints.totp"),
    config.GetString("idpui.public.url") + config.GetString("idpui.public.endpoints.delete"),
  */


  loginUrl, err := url.Parse(config.GetString("idpui.public.endpoints.login"))
  if err != nil {
    return "", err
  }

  // Redirect to after successful authentication
  wantUrl, err := url.Parse(requestedUrl)
  if err != nil {
    return "", err
  }

  // Clean query params before comparing
  q := url.Values{}

  loginUrl.RawQuery = q.Encode()
  wantUrl.RawQuery = q.Encode()

  if strings.EqualFold(wantUrl.String(), loginUrl.String()) {
    redirectTo = config.GetString("idpui.public.endpoints.root") // Do not allow landing login controller after authentication as it will create an inf. loop.
  } else {
    redirectTo = requestedUrl
  }

  return redirectTo, nil
}

func StartAuthenticationSession(env *Environment, c *gin.Context, oauth2Config *oauth2.Config, idTokenHint string, state string) (authorizationCodeUrl *url.URL, err error) {

  redirectTo, err := createPostRedirectUri(c.Request.RequestURI)
  if err != nil {
    return nil, err
  }

  if redirectTo == "" {
    return nil, errors.New("Missing redirect_to")
  }

  // Create random bytes that are based64 encoded to prevent character problems with the session store.
  // The base 64 means that more than 64 bytes are stored! Which can cause "securecookie: the value is too long"
  // To prevent this we need to use a filesystem store instead of broser cookies.
  if state == "" {
    state, err = CreateRandomStringWithNumberOfBytes(32);
    if err != nil {
      return nil, err
    }
  }

  if state == "" {
    return nil, errors.New("Missing state")
  }

  err = CreateSessionRedirect(env, c, state, redirectTo)
  if err != nil {
    return nil, err
  }

  authUrl := oauth2Config.AuthCodeURL(state)
  authorizationCodeUrl, err = url.Parse(authUrl)
  if err != nil {
    return nil, err
  }

  // Look for an id token hint to send with the request.
  if idTokenHint != "" {
    q := authorizationCodeUrl.Query()
    q.Add("id_token_hint", idTokenHint)
    authorizationCodeUrl.RawQuery = q.Encode()
  }
  // q.Add("prompt", "login") // options are none, login
  // q.Add("max_age", ?)

  return authorizationCodeUrl, err
}