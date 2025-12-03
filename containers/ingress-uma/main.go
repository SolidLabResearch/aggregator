package main

import (
	"net/http"
	"os"
	"strings"

	"ingress-uma/auth"
	"ingress-uma/signing"

	"github.com/sirupsen/logrus"
)

var ExternalHost = os.Getenv("EXTERNAL_HOST")
var DisableAuth = strings.ToLower(os.Getenv("DISABLE_AUTH")) == "true"

func init() {
	// Set up logging
	LogLevel, err := logrus.ParseLevel(strings.ToLower(os.Getenv("LOG_LEVEL")))
	if err != nil {
		LogLevel = logrus.InfoLevel
	}
	logrus.SetLevel(LogLevel)
	logrus.SetOutput(os.Stdout)
}

func main() {
	mux := http.NewServeMux()
	signing.InitSigning(mux, "/keys/private_key.pem", ExternalHost)
	auth.InitAuth(ExternalHost, DisableAuth)

	// UMA endpoints
	mux.HandleFunc("/authorize", auth.HandleAuthorizationRequest)
	mux.HandleFunc("/resources", auth.HandleResourceRequest)
	mux.HandleFunc("/policies", auth.HandlePolicyRequest)

	logrus.Info("Starting UMA RS auth server on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		logrus.Fatalf("Server failed: %v", err)
	}
}
