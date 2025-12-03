package main

import (
	"aggregator/config"
	reg "aggregator/registration"
	"aggregator/vars"
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
		vars.LogLevel = logrus.InfoLevel
	} else {
		vars.LogLevel = logLevel
	}
	logrus.SetLevel(vars.LogLevel)
	logrus.SetOutput(os.Stdout)

	// Read Network configuration from environment variables
	vars.ExternalHost = os.Getenv("AGGREGATOR_EXTERNAL_HOST")
	if vars.ExternalHost == "" {
		logrus.Fatal("Environment variables AGGREGATOR_EXTERNAL_HOST must be set")
	}
	vars.Protocol = "http"

	// Read Authorization configuration from environment variables
	vars.AggregatorASURL = os.Getenv("AS_URL")
	if vars.AggregatorASURL == "" {
		logrus.Fatal("Environment variable AS_URL must be set")
	}
	vars.AdminId = os.Getenv("ADMIN_ID")
	if vars.AdminId == "" {
		logrus.Fatal("Environment variable ADMIN_ID must be set")
	}
	vars.ClientId = os.Getenv("CLIENT_ID")
	if vars.ClientId == "" {
		logrus.Fatal("Environment variable CLIENT_ID must be set")
	}
	vars.ClientSecret = os.Getenv("CLIENT_SECRET")
	if vars.ClientSecret == "" {
		logrus.Fatal("Environment variable CLIENT_SECRET must be set")
	}
	vars.Idp = os.Getenv("IDP")
	if vars.Idp == "" {
		logrus.Fatal("Environment variable IDP must be set")
	}

	// Load in-cluster kubeConfig
	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		logrus.Fatalf("Failed to load in-cluster config: %v", err)
	}

	vars.Clientset, err = kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		logrus.Fatalf("Failed to create Kubernetes client: %v", err)
	}
	vars.DynamicClient, err = dynamic.NewForConfig(kubeConfig)
	if err != nil {
		logrus.Fatalf("Failed to create dynamic Kubernetes client: %v", err)
	}

	// Configure HTTP server
	serverMux := http.NewServeMux()

	// Configuration endpoint
	err = config.InitAdminConfiguration(serverMux)
	if err != nil {
		logrus.WithError(err).Fatalf("Failed to set up configuration endpoint")
	}

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
	mux.HandleFunc("/registration/callback", func(w http.ResponseWriter, r *http.Request) {
		reg.RegistrationCallback(w, r, mux)
	})
}
