module token-service

go 1.24.4

require github.com/coreos/go-oidc/v3 v3.17.0

require golang.org/x/sys v0.13.0 // indirect

require (
	github.com/go-jose/go-jose/v4 v4.1.3 // indirect
	github.com/sirupsen/logrus v1.9.4
	golang.org/x/oauth2 v0.35.0 // direct
)
