package main

import (
	"aggregator/config"
	"aggregator/ingress"
	"aggregator/model"
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
	model.ExternalHost = os.Getenv("EXTERNAL_HOST")
	if model.ExternalHost == "" {
		logrus.Fatal("Environment variables EXTERNAL_HOST must be set")
	}
	model.ExternalHttpPort = os.Getenv("EXTERNAL_HTTP_PORT")
	model.ExternalHttpsPort = os.Getenv("EXTERNAL_HTTPS_PORT")
	model.Protocol = strings.ToLower(os.Getenv("PROTOCOL"))
	switch model.Protocol {
	case "http":
		if model.ExternalHttpPort == "" {
			logrus.Fatal("Environment variable EXTERNAL_HTTP_PORT must be set for http protocol")
		}
	case "https":
		if model.ExternalHttpsPort == "" {
			logrus.Fatal("Environment variable EXTERNAL_HTTPS_PORT must be set for https protocol")
		}
	default:
		logrus.Fatal("Environment variables PROTOCOL must be either http or https")
	}

	// Read Aggregator Identity
	model.ID = os.Getenv("ID")
	if model.ID == "" {
		logrus.Fatal("Environment variable ID must be set")
	}
	model.Namespace = os.Getenv("NAMESPACE")
	if model.Namespace == "" {
		logrus.Fatal("Environment variable NAMESPACE must be set")
	}
	id := os.Getenv("USER_ID")
	if id == "" {
		logrus.Fatal("Environment variable USER_ID must be set")
	}
	asUrl := os.Getenv("AS_URL")
	if asUrl == "" {
		logrus.Warn("Environment variable AS_URL is empty; UMA registration is disabled")
	}
	model.Owner = model.User{
		UserId:         id,
		AuthzServerURL: asUrl,
	}
	model.ProvisionID = os.Getenv("PROVISION_ID")

	// Read spec configuration
	model.TransformationCatalog = os.Getenv("TRANSFORMATION_CATALOG")
	if model.TransformationCatalog == "" {
		logrus.Fatal("Environment variable TRANSFORMATION_CATALOG must be set.")
	}
	model.ServiceCollection = os.Getenv("SERVICE_COLLECTION")
	if model.TransformationCatalog == "" {
		logrus.Fatal("Environment variable SERVICE_COLLECTION must be set")
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

	logrus.WithFields(logrus.Fields{
		"id":                 model.ID,
		"owner_user_id":      model.Owner.UserId,
		"owner_authz_server": model.Owner.AuthzServerURL,
	}).Info("Setting up aggregator with configuration")

	// Initialize Aggregator Description
	if err := config.InitAggregatorDescription(serverMux); err != nil {
		logrus.WithError(err).Fatalf("Failed to set up aggregator description endpoint")
	}

	// Initialize service collection
	err = config.InitServiceCollection(serverMux)
	if err != nil {
		logrus.WithError(err).Fatalf("Failed to set up service collection endpoint")
	}

	// Initialize transformation catalog
	err = config.InitTransformationCatalog(serverMux)
	if err != nil {
		logrus.WithError(err).Fatalf("Failed to set up transformation catalog endpoint")
	}

	// Health check endpoint
	serverMux.HandleFunc("/healthz", healthzHandler)

	// Add middlewares
	mwMux := ingress.Chain(serverMux,
		ingress.CorsMiddleware(),
		ingress.UMAAuthMiddleware(),
		ingress.StripPrefixMiddleware(model.ID),
		ingress.LoggingMiddleware(),
	)

	// HTTP Serve
	srv := &http.Server{
		Addr:    "0.0.0.0:5000",
		Handler: mwMux,
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

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}
