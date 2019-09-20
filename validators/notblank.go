package validators

import (
  "strings"
  "gopkg.in/go-playground/validator.v9"
)

func NotBlank(fl validator.FieldLevel) bool {
  if strings.TrimSpace(fl.Field().String()) == "" {
    return false;
  }
  return true
}