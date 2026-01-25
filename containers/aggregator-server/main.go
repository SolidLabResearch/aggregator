package main

import (
	"aggregator/config"
	"aggregator/model"
	reg "aggregator/registration"
	"context"
	"fmt"
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
	model.Protocol = "http"

	// Read Authorization configuration from environment variables
	model.ClientId = os.Getenv("CLIENT_ID")
	if model.ClientId == "" {
		logrus.Fatal("Environment variable CLIENT_ID must be set")
	}

	// Standard OIDC Authorization Server configuration
	model.UMAServer = os.Getenv("AUTH_SERVER")
	if model.UMAServer == "" {
		logrus.Info("Only Solid-OIDC with Web IDs is supported (no standard OIDC Authorization Server configured)")
	} else {
		model.ClientSecret = os.Getenv("CLIENT_SECRET")
		if model.ClientSecret == "" {
			logrus.Fatal("Environment variable CLIENT_SECRET must be set")
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

	ingressClassName := os.Getenv("INGRESS_CLASS_NAME")
	if ingressClassName == "" {
		logrus.Info("No IngressClass configured. Using the default IngressClass.")
		model.IngressClassName = nil
	} else {
		model.IngressClassName = &ingressClassName
	}
	model.Namespace = os.Getenv("NAMESPACE")
	if model.Namespace == "" {
		logrus.Fatalf("Environment variable NAMESPACE must be set")
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
	/*
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
	*/

	// Healthz endpoint waits for ingress-uma to be ready
	serverMux.HandleFunc("/healthz", healthz)

	// Start HTTP server
	loggingMux := loggingMiddleware(serverMux)
	srv := &http.Server{
		Addr:    ":5000",
		Handler: loggingMux,
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

func healthz(w http.ResponseWriter, r *http.Request) {
	umaURL := fmt.Sprintf(
		"http://ingress-uma.%s.svc.cluster.local:8080/healthz",
		model.Namespace,
	)

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, umaURL, nil)
	if err != nil {
		http.Error(w, "Failed to build request", http.StatusInternalServerError)
		return
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logrus.WithError(err).Warn("ingress-uma not reachable")
		http.Error(w, "Dependency not ready", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logrus.Warnf("ingress-uma unhealthy: %d", resp.StatusCode)
		http.Error(w, "Dependency unhealthy", http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agent := r.UserAgent()
		if !strings.HasPrefix(agent, "kube-probe") {
			logrus.WithFields(logrus.Fields{
				"method": r.Method,
				"path":   r.URL.Path,
				"query":  r.URL.RawQuery,
				"remote": r.RemoteAddr,
				"agent":  agent,
			}).Debug("Incoming request")
		}
		next.ServeHTTP(w, r)
	})
}
