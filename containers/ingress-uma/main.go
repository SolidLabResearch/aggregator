package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"ingress-uma/auth"

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
	// signing.InitSigning(mux, "/keys/private_key.pem", ExternalHost)
	auth.InitAuth(ExternalHost, DisableAuth)

	// Synchronize resources (NOT SUPPORTED YET)
	// err := auth.SynchronizeResources(ASURL)
	// if err != nil {
	// 	logrus.WithError(err).Fatalf("Failed to synchronize resources with aggregator UMA server (%s)", ASURL)
	//}

	// UMA endpoints
	mux.HandleFunc("/register", auth.HandleRegistrationRequest)
	mux.HandleFunc("/authorize", auth.HandleAuthorizationRequest)
	mux.HandleFunc("/resources", auth.HandleResourceRequest)
	mux.HandleFunc("/derived-resources", auth.HandleDerivedResourceRequest)
	mux.HandleFunc("/policies", auth.HandlePolicyRequest)

	// healthz endpoint
	mux.HandleFunc("/healthz", healthz)

	// Logging middleware
	loggedMux := loggingMiddleware(mux)

	server := &http.Server{Addr: "0.0.0.0:8080", Handler: loggedMux}
	// Start HTTP server in a goroutine
	go func() {
		logrus.Info("Starting UMA RS auth server on :8080")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logrus.Fatalf("Server failed: %v", err)
		}
	}()

	// Listen for termination signals
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Block until a termination signal is received
	<-sigs
	logrus.Info("Termination signal received, starting resource cleanup")

	// Stop accepting mutations and allow active requests a short window to
	// complete before reading and deleting the in-memory resource index.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := server.Shutdown(shutdownCtx); err != nil {
		logrus.WithError(err).Warn("HTTP server did not shut down cleanly")
	}
	cancel()

	cleanupDone := make(chan struct{})
	go func() {
		defer close(cleanupDone)
		if err := auth.DeleteResources(); err != nil {
			logrus.WithError(err).Error("Failed to delete UMA resources")
		} else {
			logrus.Info("Successfully deleted all UMA resources")
		}
		auth.DeleteCredentials()
	}()

	// Leave enough time for kubelet to observe process exit before the pod's
	// 50-second grace period expires, even when an authorization server stalls.
	select {
	case <-cleanupDone:
	case <-time.After(35 * time.Second):
		logrus.Warn("UMA cleanup deadline reached; exiting")
	}

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
