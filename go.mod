module github.com/charmixer/idpui

go 1.12

require (
	github.com/charmixer/bulky v0.0.0-20191009122503-4027f55965f8
	github.com/charmixer/idp v0.0.0-20190912112817-987cd8fdbd2c
	github.com/coreos/go-oidc v2.1.0+incompatible
	github.com/gin-contrib/sessions v0.0.1
	github.com/gin-gonic/gin v1.4.0
	github.com/gofrs/uuid v3.2.0+incompatible
	github.com/gorilla/csrf v1.6.1
	github.com/gorilla/sessions v1.2.0 // indirect
	github.com/gwatts/gin-adapter v0.0.0-20170508204228-c44433c485ad
	github.com/pborman/getopt v0.0.0-20190409184431-ee0cd42419d3
	github.com/pquerna/otp v1.2.0
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/viper v1.4.0
	golang.org/x/net v0.0.0-20191007182048-72f939374954
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45
	gopkg.in/go-playground/validator.v9 v9.30.0
)

replace github.com/charmixer/idp => /Users/mnk/projects/sso/idp
