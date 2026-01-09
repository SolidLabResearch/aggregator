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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	model.ClientSecret = os.Getenv("CLIENT_SECRET")
	if model.ClientSecret == "" {
		logrus.Fatal("Environment variable CLIENT_SECRET must be set")
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

	// While we wait for instance to start the aggregator server responds with 503 to config requests
	serverMux.HandleFunc("/config/", func(w http.ResponseWriter, r *http.Request) {
		namespace := strings.TrimPrefix(r.URL.Path, "/config/")
		namespace = strings.TrimPrefix(namespace, "/")
		if namespace == "" {
			http.NotFound(w, r)
			return
		}
		if idx := strings.Index(namespace, "/"); idx != -1 {
			namespace = namespace[:idx]
		}

		if model.Clientset != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			defer cancel()
			ns, err := model.Clientset.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
			if err != nil {
				if apierrors.IsNotFound(err) {
					http.NotFound(w, r)
					return
				}
				http.Error(w, "Failed to check instance namespace", http.StatusInternalServerError)
				return
			}
			if ns.Labels["created-by"] != "aggregator" {
				http.NotFound(w, r)
				return
			}
		}

		w.Header().Set("Retry-After", "1")
		http.Error(w, "Aggregator instance not ready", http.StatusServiceUnavailable)
	})

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
