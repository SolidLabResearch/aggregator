package main

import (
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

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

	// Synchronize resources (NOT SUPPORTED YET)
	// err := auth.SynchronizeResources(ASURL)
	// if err != nil {
	// 	logrus.WithError(err).Fatalf("Failed to synchronize resources with aggregator UMA server (%s)", ASURL)
	//}

	// UMA endpoints
	mux.HandleFunc("/authorize", auth.HandleAuthorizationRequest)
	mux.HandleFunc("/resources", auth.HandleResourceRequest)
	mux.HandleFunc("/policies", auth.HandlePolicyRequest)

	// Start HTTP server in a goroutine
	go func() {
		logrus.Info("Starting UMA RS auth server on :8080")
		if err := http.ListenAndServe(":8080", mux); err != nil {
			logrus.Fatalf("Server failed: %v", err)
		}
	}()

	// Listen for termination signals
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Block until a termination signal is received
	<-sigs
	logrus.Info("Termination signal received, starting resource cleanup")

	// Keep the server running while deleting resources
	start := time.Now()
	if err := auth.DeleteResources(); err != nil {
		logrus.WithError(err).Error("Failed to delete UMA resources")
	} else {
		logrus.Info("Successfully deleted all UMA resources")
	}
	elapsed := time.Since(start)
	logrus.Infof("Resource deletion completed in %s", elapsed)

	// Now it is safe to exit
	logrus.Info("Exiting container after resource cleanup")
}
