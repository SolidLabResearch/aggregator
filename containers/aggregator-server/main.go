package main

import (
	"aggregator/config"
	"aggregator/model"
	reg "aggregator/registration"
	"context"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func main() {
	// Set up logging
	logLevel, err := logrus.ParseLevel(strings.ToLower(os.Getenv("LOG_LEVEL")))
	if err != nil {
		model.LogLevel = logrus.InfoLevel
	} else {
		model.LogLevel = logLevel
	}
	logrus.SetLevel(model.LogLevel)
	logrus.SetOutput(os.Stdout)

	// Read Network configuration from environment variables
	model.ExternalHost = os.Getenv("AGGREGATOR_EXTERNAL_HOST")
	if model.ExternalHost == "" {
		logrus.Fatal("Environment variables AGGREGATOR_EXTERNAL_HOST must be set")
	}
	model.Protocol = "http"

	// Read Authorization configuration from environment variables
	model.ClientId = os.Getenv("CLIENT_ID")
	if model.ClientId == "" {
		logrus.Fatal("Environment variable CLIENT_ID must be set")
	}

	// Standard OIDC Authorization Server configuration
	model.AuthServer = os.Getenv("AUTH_SERVER")
	if model.AuthServer == "" {
		logrus.Info("Only Solid-OIDC with Web IDs is supported (no standard OIDC Authorization Server configured)")
	} else {
		model.AggregatorSecret = os.Getenv("AGG_SECRET")
		if model.AggregatorSecret == "" {
			logrus.Fatal("Environment variable AGG_SECRET must be set")
		}
	}

	model.ProvisionClientID = os.Getenv("PROVISION_CLIENT_ID")
	model.ProvisionClientSecret = os.Getenv("PROVISION_CLIENT_SECRET")
	model.ProvisionWebID = os.Getenv("PROVISION_WEBID")
	model.ProvisionAuthorizationServer = os.Getenv("PROVISION_AUTHORIZATION_SERVER")

	allowedTypes := parseAllowedRegistrationTypes(os.Getenv("ALLOWED_REGISTRATION_TYPES"))
	model.AllowedRegistrationTypes = allowedTypes
	if hasRegistrationType(allowedTypes, "provision") {
		if model.ProvisionClientID == "" {
			logrus.Fatal("Environment variable PROVISION_CLIENT_ID must be set when provision registration is allowed")
		}
		if model.ProvisionClientSecret == "" {
			logrus.Fatal("Environment variable PROVISION_CLIENT_SECRET must be set when provision registration is allowed")
		}
		if model.ProvisionWebID == "" {
			logrus.Fatal("Environment variable PROVISION_WEBID must be set when provision registration is allowed")
		}
		if model.ProvisionAuthorizationServer == "" {
			logrus.Fatal("Environment variable PROVISION_AUTHORIZATION_SERVER must be set when provision registration is allowed")
		}
	}

	// Read disable_auth config (for testing)
	disableAuthStr := strings.ToLower(os.Getenv("DISABLE_AUTH"))
	model.DisableAuth = disableAuthStr == "true"
	if model.DisableAuth {
		logrus.Warn("⚠️  Authentication is DISABLED (DISABLE_AUTH=true) - FOR TESTING ONLY!")
	}

	// Load in-cluster kubeConfig
	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		logrus.Fatalf("Failed to load in-cluster config: %v", err)
	}

	model.Clientset, err = kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		logrus.Fatalf("Failed to create Kubernetes client: %v", err)
	}
	model.DynamicClient, err = dynamic.NewForConfig(kubeConfig)
	if err != nil {
		logrus.Fatalf("Failed to create dynamic Kubernetes client: %v", err)
	}

	// Configure HTTP server
	serverMux := http.NewServeMux()

	// Configuration endpoint
	err = config.InitTransformationsConfiguration(serverMux)
	if err != nil {
		logrus.WithError(err).Warn("Failed to set up configuration endpoint (UMA might be down)")
	}

	// Client Identifier endpoint
	config.InitClientIdentifier(serverMux)

	// Server Description endpoint
	config.InitServerDescription(serverMux)

	// Registration endpoint
	initRegistration(serverMux)

	// Start HTTP server
	srv := &http.Server{
		Addr:    ":5000",
		Handler: serverMux,
	}

	go func() {
		logrus.WithFields(logrus.Fields{"port": 5000}).Info("Server listening")
		if err := srv.ListenAndServe(); err != nil {
			logrus.WithFields(logrus.Fields{"err": err}).Error("HTTP server failed")
			os.Exit(1)
		}
	}()

	// Wait for termination signal
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	logrus.Info("Shutdown signal received, stopping server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logrus.WithError(err).Error("Server forced to shutdown")
	}

	logrus.Info("Server stopped gracefully")
}

func initRegistration(mux *http.ServeMux) {
	mux.HandleFunc("/registration", reg.RegistrationHandler)
}

func parseAllowedRegistrationTypes(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return []string{"authorization_code"}
	}

	parts := strings.Split(raw, ",")
	allowed := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.ToLower(strings.TrimSpace(part))
		if trimmed == "" {
			continue
		}
		allowed = append(allowed, trimmed)
	}

	if len(allowed) == 0 {
		return []string{"authorization_code"}
	}

	return allowed
}

func hasRegistrationType(allowed []string, target string) bool {
	for _, value := range allowed {
		if value == target {
			return true
		}
	}
	return false
}
