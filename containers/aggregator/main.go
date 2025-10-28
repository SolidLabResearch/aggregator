package main

import (
	"aggregator/auth"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Network configuration
var Protocol = "http"
var InternalHost string
var InternalPort string
var ExternalHost string
var ExternalPort string

// OICD
var webId string
var email string
var password string

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
	ExternalPort = os.Getenv("AGGREGATOR_EXTERNAL_PORT")

	if ExternalHost == "" || ExternalPort == "" {
		logrus.Fatal("Environment variables AGGREGATOR_EXTERNAL_HOST and AGGREGATOR_EXTERNAL_PORT must be set")
	}

	// ------------------------
	// Set up OIDC
	// ------------------------
	webId = os.Getenv("WEB_ID")
	email = os.Getenv("EMAIL")
	password = os.Getenv("PASSWORD")

	if webId == "" || email == "" || password == "" {
		logrus.Warn("⚠️  WARNING: Solid OIDC configuration incomplete")
		if webId == "" {
			logrus.Warn("⚠️  Missing WEB_ID environment variable")
		}
		if email == "" {
			logrus.Warn("⚠️  Missing EMAIL environment variable")
		}
		if password == "" {
			logrus.Warn("⚠️  Missing PASSWORD environment variable")
		}
		logrus.Warn("⚠️  UMA proxy will run WITHOUT authentication - requests will be passed through as-is")
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
	// Set up UMA proxy
	// ------------------------
	/* proxyConfig := proxy.ProxyConfig{
		WebId:    webId,
		Email:    email,
		Password: password,
		LogLevel: LogLevel.String(),
	}
	proxy.SetupProxy(Clientset, proxyConfig)
	*/

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
	auth.InitSigning(serverMux)
	InitializeKubernetes(serverMux)
	startConfigurationEndpoint(serverMux)
	SetupResourceRegistration()
	// InitAuthProxy(serverMux, fmt.Sprintf("%s://%s:%s", Protocol, Host, ServerPort))

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)

	<-stop // wait for signal
	logrus.Info("Shutting down gracefully...")

	// ------------------------
	// 2. Remove remaining pods
	// ------------------------
	pods, err := Clientset.CoreV1().Pods("default").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		logrus.Fatal(err)
	}
	for _, pod := range pods.Items {
		err := Clientset.CoreV1().Pods(pod.Namespace).Delete(context.Background(), pod.Name, metav1.DeleteOptions{})
		if err != nil {
			logrus.Errorf("Failed to delete pod %s/%s: %v", pod.Namespace, pod.Name, err)
		} else {
			logrus.Infof("Deleted pod: %s/%s", pod.Namespace, pod.Name)
		}
	}

	// ------------------------
	// 3. Remove remaining services
	// ------------------------
	services, err := Clientset.CoreV1().Services("default").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		logrus.Fatal(err)
	}
	for _, svc := range services.Items {
		if svc.Name == "kubernetes" {
			continue
		}
		err := Clientset.CoreV1().Services(svc.Namespace).Delete(context.Background(), svc.Name, metav1.DeleteOptions{})
		if err != nil {
			logrus.Errorf("Failed to delete service %s/%s: %v", svc.Namespace, svc.Name, err)
		} else {
			logrus.Infof("Deleted service: %s/%s", svc.Namespace, svc.Name)
		}
	}

	logrus.Infof("Cleanup complete. Exiting.")

	// let AS know that all resources need to be deleted
	auth.DeleteAllResources()
}
