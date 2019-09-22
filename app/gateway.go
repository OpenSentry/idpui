package app


import (
  "net/http"
  "golang.org/x/oauth2"
  "github.com/gin-gonic/gin"
  "github.com/gin-contrib/sessions"
  oidc "github.com/coreos/go-oidc"

  idp "github.com/charmixer/idp/client"
  "github.com/charmixer/idpui/config"
  "github.com/charmixer/idpui/environment"
)

// Use this handler as middleware to enable gateway functions in controllers
func LoadIdentity(env *environment.State) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    var idToken *oidc.IDToken

    session := sessions.Default(c)
    t := session.Get(environment.SessionIdTokenKey)
    if t == nil {
      c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Missing id_token in session"})
      return
    }

    idToken = t.(*oidc.IDToken)
    if idToken == nil {
      c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Missing id_token in session"})
      return
    }

    var accessToken *oauth2.Token
    accessToken = session.Get(environment.SessionTokenKey).(*oauth2.Token)
    idpClient := idp.NewIdpClientWithUserAccessToken(env.HydraConfig, accessToken)

    // Look up profile information for user.
    identityRequest := &idp.IdentitiesReadRequest{
      Id: idToken.Subject,
    }
    identity, err := idp.ReadIdentity(idpClient, config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.identities"), identityRequest)
    if err != nil {
      c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "Identity not found"})
      return
    }

    c.Set("identity", identity)
    c.Next()
  }
  return gin.HandlerFunc(fn)
}

func RequireIdentity(c *gin.Context) *idp.IdentitiesReadResponse {
  identity, exists := c.Get("identity")
  if exists == true {
    return identity.(*idp.IdentitiesReadResponse)
  }
  return nil
}

func IdpClientUsingAuthorizationCode(env *environment.State, c *gin.Context) (*idp.IdpClient) {
  session := sessions.Default(c)
  t := session.Get(environment.SessionTokenKey)
  if t != nil {
    accessToken := t.(*oauth2.Token)
    return idp.NewIdpClientWithUserAccessToken(env.HydraConfig, accessToken)
  }
  return nil
}

func IdpClientUsingClientCredentials(env *environment.State, c *gin.Context) (*idp.IdpClient) {
  return idp.NewIdpClient(env.IdpApiConfig)  
}