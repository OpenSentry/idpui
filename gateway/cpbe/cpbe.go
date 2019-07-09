package cpbe

import (
  "net/http"
  _ "bytes"
  _ "encoding/json"
  _ "io/ioutil"
  _ "fmt"

  "golang.org/x/net/context"
  "golang.org/x/oauth2/clientcredentials"
)

type CpBeClient struct {
  *http.Client
}

func NewCpBeClient(config *clientcredentials.Config) *CpBeClient {
  ctx := context.Background()
  client := config.Client(ctx)
  return &CpBeClient{client}
}

func IsRequiredScopesGrantedForToken(url string, client *CpBeClient, requiredScopes []string) ([]string, error) {
  // FIXME: Call cpbe to check scopes ( cpbe will probably call hydra.instropect.token)
  return requiredScopes, nil
}
