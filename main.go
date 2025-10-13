package main

import (
	"aggregator/auth"
	"aggregator/proxy"
	"flag"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

var Protocol = "http"
var Host = "localhost"
var ServerPort = "5000"
var logLevelValue = "info"

var Clientset *kubernetes.Clientset

func main() {
	// Define CLI flags for Solid OIDC configuration
	webId := flag.String("webid", "", "WebID for Solid OIDC authentication")
	email := flag.String("email", "", "Email for CSS account login")
	password := flag.String("password", "", "Password for CSS account login")
	logLevelValue := *flag.String("log-level", "info", "Logging verbosity (debug, info, warn, error)")
	flag.Parse()

	logLevel, err := logrus.ParseLevel(strings.ToLower(logLevelValue))
	if err != nil {
		logLevel = logrus.InfoLevel
	}
	logrus.SetLevel(logLevel)
	logrus.SetOutput(os.Stdout)

	config, err := clientcmd.BuildConfigFromFlags("", filepath.Join(homedir.HomeDir(), ".kube", "config"))
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("Failed to load Kubernetes config")
		os.Exit(1)
	}
	Clientset, err = kubernetes.NewForConfig(config)
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("Failed to create Kubernetes client")
		os.Exit(1)
	}

	// Validate and warn about Solid OIDC configuration
	if *webId == "" || *email == "" || *password == "" {
		logrus.Warn("⚠️  WARNING: Solid OIDC configuration incomplete")
		if *webId == "" {
			logrus.Warn("⚠️  Missing --webid argument")
		}
		if *email == "" {
			logrus.Warn("⚠️  Missing --email argument")
		}
		if *password == "" {
			logrus.Warn("⚠️  Missing --password argument")
		}
		logrus.Warn("⚠️  UMA proxy will run WITHOUT authentication - requests will be passed through as-is")
	}

	// Setup proxy with Solid OIDC configuration
	proxyConfig := proxy.ProxyConfig{
		WebId:    *webId,
		Email:    *email,
		Password: *password,
		LogLevel: logLevelValue,
	}
	proxy.SetupProxy(Clientset, proxyConfig)

	serverMux := http.NewServeMux()
	go func() {
		logrus.WithFields(logrus.Fields{"port": ServerPort}).Info("Server listening")
		if err := http.ListenAndServe(":"+ServerPort, serverMux); err != nil {
			logrus.WithFields(logrus.Fields{"err": err}).Error("HTTP server failed")
			os.Exit(1)
		}
	}()
	auth.InitSigning(serverMux)
	InitializeKubernetes(serverMux)
	startConfigurationEndpoint(serverMux)
	SetupResourceRegistration()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	<-stop // wait for signal
	logrus.Info("Shutting down gracefully...")
	// remove all pods (including proxy?)
	pods, err := Clientset.CoreV1().Pods("default").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("Failed to list pods during shutdown")
		os.Exit(1)
	}

	for _, pod := range pods.Items {
		err := Clientset.CoreV1().Pods(pod.Namespace).Delete(context.Background(), pod.Name, metav1.DeleteOptions{})
		if err != nil {
			logrus.WithFields(logrus.Fields{"namespace": pod.Namespace, "name": pod.Name, "err": err}).Error("Failed to delete pod")
		} else {
			logrus.WithFields(logrus.Fields{"namespace": pod.Namespace, "name": pod.Name}).Info("Deleted pod")
		}
	}

	services, err := Clientset.CoreV1().Services("default").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("Failed to list services during shutdown")
		os.Exit(1)
	}

	for _, svc := range services.Items {
		// Skip the critical Kubernetes API service
		if svc.Name == "kubernetes" {
			continue
		}
		err := Clientset.CoreV1().Services(svc.Namespace).Delete(context.Background(), svc.Name, metav1.DeleteOptions{})
		if err != nil {
			logrus.WithFields(logrus.Fields{"namespace": svc.Namespace, "name": svc.Name, "err": err}).Error("Failed to delete service")
		} else {
			logrus.WithFields(logrus.Fields{"namespace": svc.Namespace, "name": svc.Name}).Info("Deleted service")
		}
	}

	logrus.Info("Cleanup complete. Exiting.")

	// let AS know that all resources need to be deleted
	auth.DeleteAllResources()
}
