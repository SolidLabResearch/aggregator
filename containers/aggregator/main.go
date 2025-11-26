package main

import (
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

// Network configuration
var Protocol = "http"
var ExternalHost string

// Authorization configuration
var AggregatorASURL string
var AdminId string
var ClientId string
var ClientSecret string
var Idp string

// Logging configuration
var LogLevel logrus.Level

// Kubernetes client
var Clientset *kubernetes.Clientset
var DynamicClient *dynamic.DynamicClient

func main() {
	// Set up logging
	LogLevel, err := logrus.ParseLevel(strings.ToLower(os.Getenv("LOG_LEVEL")))
	if err != nil {
		LogLevel = logrus.InfoLevel
	}
	logrus.SetLevel(LogLevel)
	logrus.SetOutput(os.Stdout)

	// Read Network configuration from environment variables
	ExternalHost = os.Getenv("AGGREGATOR_EXTERNAL_HOST")
	if ExternalHost == "" {
		logrus.Fatal("Environment variables AGGREGATOR_EXTERNAL_HOST must be set")
	}

	// Read Authorization configuration from environment variables
	AggregatorASURL = os.Getenv("AS_URL")
	if AggregatorASURL == "" {
		logrus.Fatal("Environment variable AS_URL must be set")
	}
	AdminId = os.Getenv("ADMIN_ID")
	if AdminId == "" {
		logrus.Fatal("Environment variable ADMIN_ID must be set")
	}
	ClientId = os.Getenv("CLIENT_ID")
	if ClientId == "" {
		logrus.Fatal("Environment variable CLIENT_ID must be set")
	}
	ClientSecret = os.Getenv("CLIENT_SECRET")
	if ClientSecret == "" {
		logrus.Fatal("Environment variable CLIENT_SECRET must be set")
	}
	Idp = os.Getenv("IDP")
	if Idp == "" {
		logrus.Fatal("Environment variable IDP must be set")
	}

	// Load in-cluster kubeConfig
	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		logrus.Fatalf("Failed to load in-cluster config: %v", err)
	}

	Clientset, err = kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		logrus.Fatalf("Failed to create Kubernetes client: %v", err)
	}
	DynamicClient, err = dynamic.NewForConfig(kubeConfig)
	if err != nil {
		logrus.Fatalf("Failed to create dynamic Kubernetes client: %v", err)
	}

	// Configure HTTP server
	serverMux := http.NewServeMux()
	initUserRegistration(serverMux)
	initAdminConfiguration(serverMux)

	serverMux.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Custom-Header", "CustomValue")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Error not intercepted"))
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
