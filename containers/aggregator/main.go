package main

import (
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Network configuration
var Protocol = "http"
var InternalHost string
var InternalPort string
var ExternalHost string

// Logging
var LogLevel logrus.Level

var Clientset *kubernetes.Clientset

func main() {
	// ------------------------
	// Set up logging
	// ------------------------
	LogLevel, err := logrus.ParseLevel(strings.ToLower(os.Getenv("LOG_LEVEL")))
	if err != nil {
		LogLevel = logrus.InfoLevel
	}
	logrus.SetLevel(LogLevel)
	logrus.SetOutput(os.Stdout)

	// ------------------------
	// Read host and port from environment variables
	// ------------------------
	InternalHost = os.Getenv("AGGREGATOR_HOST")
	InternalPort = os.Getenv("AGGREGATOR_PORT")

	if InternalHost == "" || InternalPort == "" {
		logrus.Fatal("Environment variables AGGREGATOR_HOST and AGGREGATOR_PORT must be set")
	}

	ExternalHost = os.Getenv("AGGREGATOR_EXTERNAL_HOST")

	if ExternalHost == "" {
		logrus.Fatal("Environment variables AGGREGATOR_EXTERNAL_HOST must be set")
	}

	// ------------------------
	// Load in-cluster kubeConfig
	// ------------------------
	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		logrus.Fatalf("Failed to load in-cluster config: %v", err)
	}

	Clientset, err = kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		logrus.Fatalf("Failed to create Kubernetes client: %v", err)
	}

	// ------------------------
	// Start HTTP server
	// ------------------------
	serverMux := http.NewServeMux()
	go func() {
		logrus.WithFields(logrus.Fields{"port": InternalPort}).Info("Server listening")
		if err := http.ListenAndServe(":"+InternalPort, serverMux); err != nil {
			logrus.WithFields(logrus.Fields{"err": err}).Error("HTTP server failed")
			os.Exit(1)
		}
	}()
	InitializeKubernetes(serverMux)
	configData := startConfigurationEndpoint(serverMux)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)

	<-stop // wait for signal
	logrus.Info("Shutting down gracefully...")

	// Stop all pipelines
	for ns, pipeline := range configData.pipelines {
		logrus.Infof("Stopping pipeline in namespace: %s", ns)
		err := pipeline.Stop()
		if err != nil {
			logrus.Errorf("Failed to stop pipeline %s: %v", ns, err)
		}
	}

	logrus.Infof("Cleanup complete. Exiting.")
}
