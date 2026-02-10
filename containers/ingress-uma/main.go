package main

import (
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"ingress-uma/auth"

	"github.com/sirupsen/logrus"
)

var ExternalHost = os.Getenv("EXTERNAL_HOST")
var DisableAuth = strings.ToLower(os.Getenv("DISABLE_AUTH")) == "true"
var ClientId = os.Getenv("CLIENT_ID")

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
	// signing.InitSigning(mux, "/keys/private_key.pem", ExternalHost)
	auth.InitAuth(ExternalHost, DisableAuth, ClientId)

	// Synchronize resources (NOT SUPPORTED YET)
	// err := auth.SynchronizeResources(ASURL)
	// if err != nil {
	// 	logrus.WithError(err).Fatalf("Failed to synchronize resources with aggregator UMA server (%s)", ASURL)
	//}

	// UMA endpoints
	mux.HandleFunc("/register", auth.HandleRegistrationRequest)
	mux.HandleFunc("/authorize", auth.HandleAuthorizationRequest)
	mux.HandleFunc("/resources", auth.HandleResourceRequest)
	mux.HandleFunc("/policies", auth.HandlePolicyRequest)

	// healthz endpoint
	mux.HandleFunc("/healthz", healthz)

	// Logging middleware
	loggedMux := loggingMiddleware(mux)

	// Start HTTP server in a goroutine
	go func() {
		logrus.Info("Starting UMA RS auth server on :8080")
		if err := http.ListenAndServe("0.0.0.0:8080", loggedMux); err != nil {
			logrus.Fatalf("Server failed: %v", err)
		}
	}()

	// Listen for termination signals
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Block until a termination signal is received
	<-sigs
	logrus.Info("Termination signal received, starting resource cleanup")

	// Clean up UMA resources
	if err := auth.DeleteResources(); err != nil {
		logrus.WithError(err).Error("Failed to delete UMA resources")
	} else {
		logrus.Info("Successfully deleted all UMA resources")
	}

	// Clean up credentials
	auth.DeleteCredentials()

	logrus.Info("Exiting container after resource cleanup")
}

func healthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logrus.WithFields(logrus.Fields{
			"method": r.Method,
			"path":   r.URL.Path,
			"query":  r.URL.RawQuery,
			"remote": r.RemoteAddr,
			"agent":  r.UserAgent(),
		}).Debug("Incoming request")

		next.ServeHTTP(w, r)
	})
}
