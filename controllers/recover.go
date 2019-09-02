package controllers

import (
  "net/http"
  "strings"
  "github.com/sirupsen/logrus"
  "github.com/gin-gonic/gin"
  "github.com/gorilla/csrf"
  "github.com/gin-contrib/sessions"
  idp "github.com/charmixer/idp/client"
  
  "github.com/charmixer/idpui/config"
  "github.com/charmixer/idpui/environment"
)

type recoverForm struct {
    Identity string `form:"identity" binding:"required"`
}

func ShowRecover(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "ShowRecover",
    })

    session := sessions.Default(c)

    // See if a failed authenticate submit is present and prefill the recover field.
    username := session.Get("authenticate.username")

    errors := session.Flashes("recover.errors")
    err := session.Save() // Remove flashes read, and save submit fields
    if err != nil {
      log.Debug(err.Error())
    }

    var errorIdentity string

    if len(errors) > 0 {
      errorsMap := errors[0].(map[string][]string)
      for k, v := range errorsMap {
        if k == "errorIdentity" && len(v) > 0 {
          errorIdentity = strings.Join(v, ", ")
        }
      }
    }

    c.HTML(200, "recover.html", gin.H{
      "__links": []map[string]string{
        {"href": "/public/css/main.css"},
      },
      "__title": "Recover",
      csrf.TemplateTag: csrf.TemplateField(c.Request),
      "username": username,
      "errorIdentity": errorIdentity,
    })
  }
  return gin.HandlerFunc(fn)
}

func SubmitRecover(env *environment.State, route environment.Route) gin.HandlerFunc {
  fn := func(c *gin.Context) {

    log := c.MustGet(environment.LogKey).(*logrus.Entry)
    log = log.WithFields(logrus.Fields{
      "func": "SubmitRecover",
    })

    var form recoverForm
    err := c.Bind(&form)
    if err != nil {
      // Do better error handling in the application.
      c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
      c.Abort()
      return
    }

    session := sessions.Default(c)

    errors := make(map[string][]string)

    identity := strings.TrimSpace(form.Identity)
    if identity == "" {
      errors["errorIdentity"] = append(errors["errorIdentity"], "Not found")
    }

    idpClient := idp.NewIdpApiClient(env.IdpApiConfig)

    recoverRequest := idp.RecoverRequest{
      Id: form.Identity,
    }
    recoverResponse, err := idp.Recover(config.GetString("idp.public.url") + config.GetString("idp.public.endpoints.recover"), idpClient, recoverRequest)
    if err != nil {
      log.Debug(err.Error())
      errors["errorIdentity"] = append(errors["errorIdentity"], "Not found")
    }

    if len(errors) > 0 {

      session.Set("authenticate.username", recoverRequest.Id)

      session.AddFlash(errors, "recover.errors")
      err = session.Save()
      if err != nil {
        log.Debug(err.Error())
      }
      log.WithFields(logrus.Fields{"redirect_to": route.URL}).Debug("Redirecting")
      c.Redirect(http.StatusFound, route.URL)
      c.Abort();
      return
    }

    // Propagate selected user to verification controller to keep urls clean
    session.Set("recoververification.username", recoverResponse.Id)

    // Cleanup session
    session.Delete("authenticate.username")
    session.Delete("recover.errors")

    err = session.Save()
    if err != nil {
      log.Debug(err.Error())
    }

    log.WithFields(logrus.Fields{
      "redirect_to": recoverResponse.RedirectTo,
    }).Debug("Redirecting");
    c.Redirect(http.StatusFound, recoverResponse.RedirectTo)
    c.Abort()
  }
  return gin.HandlerFunc(fn)
}
