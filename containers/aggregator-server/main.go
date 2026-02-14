package main

import (
	"aggregator/config"
	"aggregator/instance"
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
	model.ExternalHost = os.Getenv("EXTERNAL_HOST")
	if model.ExternalHost == "" {
		logrus.Fatal("Environment variable EXTERNAL_HOST must be set")
	}
	model.TLSSecret = os.Getenv("TLS_SECRET")
	if model.TLSSecret != "" {
		logrus.Info("HTTPS enabled!")
		model.Protocol = "https"
	} else {
		model.Protocol = "http"
	}

	// Read Authorization configuration from environment variables
	missingRequired := make([]string, 0, 3)

	model.ClientId = os.Getenv("CLIENT_ID")
	if model.ClientId == "" {
		missingRequired = append(missingRequired, "CLIENT_ID")
	}

	// Registration Authorization configuration
	allowedTypes := parseAllowedRegistrationTypes(os.Getenv("ALLOWED_REGISTRATION_TYPES"))
	model.AllowedRegistrationTypes = allowedTypes
	if hasRegistrationType(allowedTypes, "provision") {
		model.ProvisionClientID = strings.TrimSpace(os.Getenv("PROVISION_CLIENT_ID"))
		model.ProvisionClientSecret = strings.TrimSpace(os.Getenv("PROVISION_CLIENT_SECRET"))
		model.ProvisionWebID = strings.TrimSpace(os.Getenv("PROVISION_WEBID"))
		model.ProvisionIDP = strings.TrimSpace(os.Getenv("PROVISION_IDP"))
		model.ProvisionAuthorizationServer = strings.TrimSpace(os.Getenv("PROVISION_AUTHORIZATION_SERVER"))
		model.IDPServerType = strings.ToLower(strings.TrimSpace(os.Getenv("IDP_SERVER_TYPE")))
		if model.ProvisionClientID == "" {
			missingRequired = append(missingRequired, "PROVISION_CLIENT_ID (required for provision registration)")
		}
		if model.ProvisionClientSecret == "" {
			missingRequired = append(missingRequired, "PROVISION_CLIENT_SECRET (required for provision registration)")
		}
		if model.ProvisionWebID == "" {
			missingRequired = append(missingRequired, "PROVISION_WEBID (required for provision registration)")
		}
		if model.ProvisionAuthorizationServer == "" {
			missingRequired = append(missingRequired, "PROVISION_AUTHORIZATION_SERVER (required for provision registration)")
		}
	}

	model.AuthServer = os.Getenv("AUTH_SERVER")
	if model.AuthServer == "" {
		if hasRegistrationType(allowedTypes, "device_code") {
			missingRequired = append(missingRequired, "AUTH_SERVER (required for device_code registration)")
		} else {
			logrus.Info("Only Solid-OIDC with Web IDs is supported (no standard OIDC Authorization Server configured)")
		}
	}

	if model.AuthServer != "" || hasRegistrationType(allowedTypes, "client_credentials") {
		secretBytes, err := os.ReadFile("/etc/secrets/clientSecret")
		if err != nil {
			logrus.Fatalf("Failed to read CLIENT_SECRET from mounted secret: %v", err)
		}

		model.ClientSecret = strings.TrimSpace(string(secretBytes))
		if model.ClientSecret == "" {
			logrus.Fatal("Mounted CLIENT_SECRET is empty")
		}
	}

	// Log missing required authorization variables and exit if any are missing
	if len(missingRequired) > 0 {
		logrus.WithField("missing_variables", missingRequired).
			Fatal("Missing required environment variables")
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
		logrus.Warn("No IngressClass configured. Using the default IngressClass.")
		model.IngressClassName = nil
	} else {
		model.IngressClassName = &ingressClassName
	}
	model.Namespace = os.Getenv("NAMESPACE")
	if model.Namespace == "" {
		logrus.Fatalf("Environment variable NAMESPACE must be set")
	}

	// Read spec configuration
	model.TransformationCatalog = os.Getenv("TRANSFORMATION_CATALOG")
	if model.TransformationCatalog == "" {
		logrus.Warn("Environment variable TRANSFORMATION_CATALOG was not set. default=/transformations")
		model.TransformationCatalog = "/transformations"
	}
	model.ServiceCollection = os.Getenv("SERVICE_COLLECTION")
	if model.ServiceCollection == "" {
		logrus.Warn("Environment variable SERVICE_COLLECTION was not set. default=/services")
		model.ServiceCollection = "/services"
	}
	model.RegistrationEndpoint = os.Getenv("REGISTRATION")
	if model.RegistrationEndpoint == "" {
		logrus.Warn("Environment variable REGISTRATION was not set. default=/registration")
		model.ServiceCollection = "/registration"
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
	serverMux.HandleFunc(model.RegistrationEndpoint, reg.RegistrationHandler)

	// Status endpoint
	serverMux.HandleFunc("/status", statusHandler)

	// Healthz endpoint waits for ingress-uma to be ready
	serverMux.HandleFunc("/healthz", healthzHandler)

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

func statusHandler(w http.ResponseWriter, r *http.Request) {
	aggregatorID := strings.TrimPrefix(r.URL.Path, "/status/")
	if aggregatorID == "" {
		http.Error(w, "missing aggregator id", http.StatusBadRequest)
		return
	}

	// 1 Check if aggregator instance exists in your system
	_, err := instance.GetAggregatorInstance(aggregatorID)
	if err != nil {
		http.Error(w, "aggregator not found", http.StatusNotFound)
		return
	}

	labelSelector := fmt.Sprintf("agg.knows.idlab.ugent.be/id=%s", aggregatorID)

	// 2 Check Deployment
	deployments, err := model.Clientset.AppsV1().
		Deployments(model.Namespace).
		List(r.Context(), metav1.ListOptions{
			LabelSelector: labelSelector,
		})
	if err != nil {
		http.Error(w, "failed to query deployment", http.StatusInternalServerError)
		return
	}

	if len(deployments.Items) == 0 {
		http.Error(w, "deployment not found", http.StatusTooEarly)
		return
	}

	deployment := deployments.Items[0]
	if deployment.Status.ReadyReplicas < *deployment.Spec.Replicas {
		w.Header().Set("Retry-After", "3")
		http.Error(w, "deployment not ready", http.StatusServiceUnavailable)
		return
	}

	// 3 Check Service
	services, err := model.Clientset.CoreV1().
		Services(model.Namespace).
		List(r.Context(), metav1.ListOptions{
			LabelSelector: labelSelector,
		})
	if err != nil {
		http.Error(w, "failed to query service", http.StatusInternalServerError)
		return
	}

	if len(services.Items) == 0 {
		http.Error(w, "service not found", http.StatusTooEarly)
		return
	}

	// 4 Check Ingress
	ingresses, err := model.Clientset.NetworkingV1().
		Ingresses(model.Namespace).
		List(r.Context(), metav1.ListOptions{
			LabelSelector: labelSelector,
		})
	if err != nil {
		http.Error(w, "failed to query ingress", http.StatusInternalServerError)
		return
	}

	if len(ingresses.Items) == 0 {
		http.Error(w, "ingress not found", http.StatusTooEarly)
		return
	}

	// 5 Check actual service health endpoint
	serviceURL := fmt.Sprintf(
		"http://%s.%s.svc.cluster.local:5000/healthz",
		services.Items[0].Name,
		model.Namespace,
	)

	resp, err := model.HttpClient.Get(serviceURL)
	if err != nil || resp.StatusCode != http.StatusOK {
		http.Error(w, "service not healthy", http.StatusTooEarly)
		return
	}
	defer resp.Body.Close()

	// ✅ All good
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ready"))
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
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
