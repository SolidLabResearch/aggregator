package main

import (
	"aggregator/auth"
	"aggregator/proxy"
	"flag"
	"fmt"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

var Protocol = "http"
var Host = "localhost"
var ServerPort = "5000"
var LogLevel = logrus.InfoLevel

var Clientset *kubernetes.Clientset

// getEnv returns the value of the environment variable if set (and non-empty), otherwise the fallback.
func getEnv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// getEnvFirst returns the first non-empty environment variable value among keys, otherwise the fallback.
func getEnvFirst(keys []string, fallback string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return fallback
}

func main() {
	webId := flag.String("webid", getEnv("WEBID", ""), "WebID for Solid OIDC authentication")
	email := flag.String("email", getEnv("EMAIL", ""), "Email for CSS account login")
	password := flag.String("password", getEnv("PASSWORD", ""), "Password for CSS account login")
	logLevelPtr := flag.String("log-level", getEnv("LOG_LEVEL", "info"), "Logging verbosity (debug, info, warn, error)")
	flag.Parse()

	Protocol = getEnv("PROTOCOL", Protocol)
	Host = getEnv("HOST", Host)
	ServerPort = getEnvFirst([]string{"PORT", "SERVER_PORT"}, ServerPort)

	logLevelValue := strings.ToLower(*logLevelPtr)
	parsedLevel, err := logrus.ParseLevel(logLevelValue)
	if err != nil {
		parsedLevel = logrus.InfoLevel
	}
	LogLevel = parsedLevel
	logrus.SetLevel(LogLevel)
	logrus.SetOutput(os.Stdout)

	// Initialize Kubernetes client: try in-cluster, then KUBECONFIG; if neither works, exit with error
	var kubeCfg *rest.Config
	var kubeErr error
	if strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST")) != "" || strings.TrimSpace(os.Getenv("IN_CLUSTER")) == "1" {
		kubeCfg, kubeErr = rest.InClusterConfig()
		if kubeErr != nil {
			logrus.WithError(kubeErr).Warn("In-cluster Kubernetes config not available; falling back to KUBECONFIG")
		}
	}
	if kubeCfg == nil {
		kubeconfigPath := getEnv("KUBECONFIG", filepath.Join(homedir.HomeDir(), ".kube", "config"))
		kubeCfg, kubeErr = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	}
	if kubeCfg == nil || kubeErr != nil {
		logrus.WithError(kubeErr).Error("No Kubernetes configuration found. Set KUBECONFIG, mount your kubeconfig into the container, or run in-cluster.")
		os.Exit(1)
	}
	Clientset, err = kubernetes.NewForConfig(kubeCfg)
	if err != nil {
		logrus.WithError(err).Error("Failed to create Kubernetes client")
		os.Exit(1)
	}

	// Validate and warn about Solid OIDC configuration
	if *webId == "" || *email == "" || *password == "" {
		logrus.Warn("⚠️  WARNING: Solid OIDC configuration incomplete")
		if *webId == "" {
			logrus.Warn("⚠️  Missing webid (set --webid or WEBID)")
		}
		if *email == "" {
			logrus.Warn("⚠️  Missing email (set --email or EMAIL)")
		}
		if *password == "" {
			logrus.Warn("⚠️  Missing password (set --password or PASSWORD)")
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
	InitAuthProxy(serverMux, fmt.Sprintf("%s://%s:%s", Protocol, Host, ServerPort))

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)

	<-stop
	logrus.Info("Shutting down gracefully...")

	pods, err := Clientset.CoreV1().Pods("default").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("Failed to list pods during shutdown")
		os.Exit(1)
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 30)
	for _, pod := range pods.Items {
		p := pod
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			err := Clientset.CoreV1().Pods(p.Namespace).Delete(ctx, p.Name, metav1.DeleteOptions{})
			if err != nil {
				logrus.WithFields(logrus.Fields{"namespace": p.Namespace, "name": p.Name, "err": err}).Error("Failed to delete pod")
			} else {
				logrus.WithFields(logrus.Fields{"namespace": p.Namespace, "name": p.Name}).Info("Deleted pod")
			}
		}()
	}
	services, err := Clientset.CoreV1().Services("default").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("Failed to list services during shutdown")
		os.Exit(1)
	}
	for _, svc := range services.Items {
		if svc.Name == "kubernetes" {
			continue
		}
		s := svc // capture loop var
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			err := Clientset.CoreV1().Services(s.Namespace).Delete(ctx, s.Name, metav1.DeleteOptions{})
			if err != nil {
				logrus.WithFields(logrus.Fields{"namespace": s.Namespace, "name": s.Name, "err": err}).Error("Failed to delete service")
			} else {
				logrus.WithFields(logrus.Fields{"namespace": s.Namespace, "name": s.Name}).Info("Deleted service")
			}
		}()
	}
	auth.DeleteAllResources()
	wg.Wait()
	logrus.Info("Cleanup complete. Exiting.")
}
