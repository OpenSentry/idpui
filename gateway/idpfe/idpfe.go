package idpfe

import (
  "golang.org/x/oauth2"
  "golang.org/x/oauth2/clientcredentials"
  "github.com/gin-gonic/gin"
  "golang-idp-fe/config"
  "golang-idp-fe/interfaces"
  "golang-idp-fe/gateway/idpbe"
  "errors"
  _ "fmt"
)

func RequestAccessTokenForIdpBe(provider *clientcredentials.Config) (*oauth2.Token, error) {
  var token *oauth2.Token
  token, err := provider.Token(oauth2.NoContext)
  if err != nil {
    return token, err
  }
  return token, nil
}

func FetchProfileForContext(c *gin.Context) (interfaces.Profile, error) {
  var profile interfaces.Profile

  token, accessTokenExists := c.Get("access_token")
  if accessTokenExists != true {
    return profile, errors.New("No access token found in context")
  }
  var accessToken string = token.(string)

  // Check access token for identity
  // TODO: Can we get rid of this call and find the identity directly in the access token by setting IdToken in the context?
  var userInfoResponse interfaces.UserInfoResponse
  var err error
  userInfoResponse, err = idpbe.FetchIdentityFromAccessToken(config.Hydra.UserInfoUrl, accessToken)
  if err != nil {
    return profile, err
  }
  var id string = userInfoResponse.Sub;

  // Use token to call idp-be as idp-fe on behalf of the user to fetch profile information.
  var identityResponse interfaces.IdentityResponse
  request := interfaces.IdentityRequest{
    Id: id,
  }
  identityResponse, err = idpbe.FetchProfileForIdentity(config.IdpBe.IdentitiesUrl, accessToken, request)
  if err != nil {
    return profile, err
  }

  profile = interfaces.Profile{
    Id: identityResponse.Id,
    Name: identityResponse.Name,
    Email: identityResponse.Email,
  }
  return profile, nil
}
