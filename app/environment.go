package app

import (
  "strings"
  "time"
  "net/http"
  "golang.org/x/oauth2"
  "golang.org/x/oauth2/clientcredentials"
  oidc "github.com/coreos/go-oidc"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gofrs/uuid"

  "github.com/charmixer/idpui/utils"
)

type IdentityStore struct {
  Token *oauth2.Token
  IdToken string
}

type EnvironmentConstants struct {
  RequestIdKey   string
  LogKey         string
  AccessTokenKey string
  IdTokenKey     string

  SessionCredentialsStoreKey string // This hold the access token and id token
  SessionStoreKey            string // This holds the application data
  SessionExchangeStateKey    string
  SessionClaimStateKey       string
  SessionLogoutStateKey      string

  ContextAccessTokenKey string
  ContextIdTokenKey string
  ContextIdTokenRawKey string
  ContextIdTokenHintKey string
  ContextIdentityKey string

  IdentityStoreKey string
}

type Environment struct {
  Constants *EnvironmentConstants

  Logger *logrus.Logger

  Provider        *oidc.Provider
  OAuth2Delegator *oauth2.Config // hydra

  IdpConfig *clientcredentials.Config
  AapConfig *clientcredentials.Config
}


func RequestLogger(env *Environment, appFields logrus.Fields) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    // Start timer
    start := time.Now()
    path := c.Request.URL.Path
    raw := c.Request.URL.RawQuery

    var requestId string = c.MustGet(env.Constants.RequestIdKey).(string)
    requestLog := env.Logger.WithFields(appFields).WithFields(logrus.Fields{
      "request.id": requestId,
    })
    c.Set(env.Constants.LogKey, requestLog)

    c.Next()

    // Stop timer
    stop := time.Now()
    latency := stop.Sub(start)

    ipData, err := utils.GetRequestIpData(c.Request)
    if err != nil {
      env.Logger.WithFields(appFields).WithFields(logrus.Fields{
        "func": "RequestLogger",
      }).Debug(err.Error())
    }

    forwardedForIpData, err := utils.GetForwardedForIpData(c.Request)
    if err != nil {
      env.Logger.WithFields(appFields).WithFields(logrus.Fields{
        "func": "RequestLogger",
      }).Debug(err.Error())
    }

  method := c.Request.Method
  statusCode := c.Writer.Status()
  errorMessage := c.Errors.ByType(gin.ErrorTypePrivate).String()

  bodySize := c.Writer.Size()

    var fullpath string = path
  if raw != "" {
  fullpath = path + "?" + raw
  }

  // if public data is requested successfully, then dont log it since its just spam when debugging
  if strings.Contains(path, "/public/") && ( statusCode == http.StatusOK || statusCode == http.StatusNotModified ) {
   return
  }

  logrus.WithFields(appFields).WithFields(logrus.Fields{
      "latency": latency,
      "forwarded_for.ip": forwardedForIpData.Ip,
      "forwarded_for.port": forwardedForIpData.Port,
      "ip": ipData.Ip,
      "port": ipData.Port,
      "method": method,
      "status": statusCode,
      "error": errorMessage,
      "body_size": bodySize,
      "path": fullpath,
      "request.id": requestId,
    }).Info("")
  }
  return gin.HandlerFunc(fn)
}

func RequestId() gin.HandlerFunc {
  return func(c *gin.Context) {
  // Check for incoming header, use it if exists
  requestID := c.Request.Header.Get("X-Request-Id")

  // Create request id with UUID4
  if requestID == "" {
  uuid4, _ := uuid.NewV4()
  requestID = uuid4.String()
  }

  // Expose it for use in the application
  c.Set("RequestId", requestID)

  // Set X-Request-Id header
  c.Writer.Header().Set("X-Request-Id", requestID)
  c.Next()
  }
}