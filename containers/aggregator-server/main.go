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
	model.ExternalHttpPort = os.Getenv("EXTERNAL_HTTP_PORT")
	if model.ExternalHttpPort == "" {
		logrus.Warn("Environment variable EXTERNAL_HTTP_PORT was not set. default=80")
		model.ExternalHttpPort = "80"
	}
	model.ExternalHttpsPort = os.Getenv("EXTERNAL_HTTPS_PORT")
	if model.ExternalHttpsPort == "" {
		logrus.Warn("Environment variable EXTERNAL_HTTPS_PORT was not set. default=443")
		model.ExternalHttpsPort = "443"
	}

	model.TLSSecret = os.Getenv("TLS_SECRET")
	if model.TLSSecret != "" {
		logrus.Info("HTTPS enabled!")
		model.Protocol = "https"
	} else {
		model.Protocol = "http"
	}

	// Read Authentication configuration from environment variables
	missingRequired := make([]string, 0, 3)

	// Standard OIDC
	model.OIDCClientId = os.Getenv("OIDC_CLIENT_ID")
	model.OIDCServer = os.Getenv("OIDC_SERVER")
	secretBytes, err := os.ReadFile("/etc/secrets/oidcSecret")
	if err == nil {
		model.OIDCClientSecret = strings.TrimSpace(string(secretBytes))
	}

	// Solid OIDC
	solidOIDCEnabled := os.Getenv("SOLID_OIDC") == "true"
	if solidOIDCEnabled {
		logrus.Info("Solid-OIDC with Web IDs is supported")
	}

	// Allowed registration types
	allowedTypes := parseAllowedRegistrationTypes(os.Getenv("ALLOWED_REGISTRATION_TYPES"))
	model.AllowedRegistrationTypes = allowedTypes

	if model.OIDCClientId == "" || model.OIDCClientSecret == "" || model.OIDCServer == "" {
		// Need atleast one OIDC flow
		if !solidOIDCEnabled {
			logrus.Fatal("Atleast one OIDC flow (standard/solid) should be configured")
		}
		// Device code
		if hasRegistrationType(allowedTypes, "device_code") {
			logrus.Fatal("Device code flow needs a configured standard oidc flow")
		}
	} else {
		logrus.Info("Standard OIDC with central IDP is supported")
	}

	// Provision
	if hasRegistrationType(allowedTypes, "provision") {
		model.ProvisionClientID = strings.TrimSpace(os.Getenv("PROVISION_CLIENT_ID"))
		model.ProvisionClientSecret = strings.TrimSpace(os.Getenv("PROVISION_CLIENT_SECRET"))
		model.ProvisionWebID = strings.TrimSpace(os.Getenv("PROVISION_WEBID"))
		model.ProvisionIDP = strings.TrimSpace(os.Getenv("PROVISION_IDP"))
		model.ProvisionAuthorizationServer = strings.TrimSpace(os.Getenv("PROVISION_AUTHORIZATION_SERVER"))
		model.IDPServerType = strings.ToLower(strings.TrimSpace(os.Getenv("IDP_SERVER_TYPE")))
		if model.ProvisionClientID == "" {
			missingRequired = append(missingRequired, "auth.provision.ClientId (required for provision registration)")
		}
		if model.ProvisionClientSecret == "" {
			missingRequired = append(missingRequired, "auth.provision.clientSecret (required for provision registration)")
		}
		if model.ProvisionWebID == "" {
			missingRequired = append(missingRequired, "auth.provision.webId (required for provision registration)")
		}
		if model.ProvisionAuthorizationServer == "" {
			missingRequired = append(missingRequired, "auth.provision.server (required for provision registration)")
		}
	}

	if !hasRegistrationType(allowedTypes, "client_credentials") && model.OIDCClientSecret == "" {
		model.ClientCredId = os.Getenv("CLIENT_CRED_ID")
		if model.ClientCredId == "" {
			missingRequired = append(missingRequired, "auth.client_credentials.clientId (required for client_credentials registration)")
		}

		secretBytes, err := os.ReadFile("/etc/secrets/credSecret")
		if err == nil {
			model.ClientCredSecret = strings.TrimSpace(string(secretBytes))
		}
		if model.ClientCredSecret == "" {
			missingRequired = append(missingRequired, "auth.client_credentias.clientSecret (required for client_credentials registration)")
		}
	}

	// Log missing required authorization variables and exit if any are missing
	if len(missingRequired) > 0 {
		logrus.WithField("missing_variables", missingRequired).
			Fatal("Missing required environment variables")
	}

	// Log allowed registration types
	logrus.Infof("Allowed registration types: %s", allowedTypes)

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

	// Solid Client Identifier endpoint
	if solidOIDCEnabled {
		config.InitClientIdentifier(serverMux)
	}

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
	corsMux := corsMiddleware(loggingMux)
	srv := &http.Server{
		Addr:    ":5000",
		Handler: corsMux,
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
	logrus.Info("aggregator-server is healthy")
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

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		origin := r.Header.Get("Origin")
		if origin != "" {
			// Echo origin (required for credentials)
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}

		// Allow all methods you care about
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH")

		// Echo requested headers
		reqHeaders := r.Header.Get("Access-Control-Request-Headers")
		if reqHeaders != "" {
			w.Header().Set("Access-Control-Allow-Headers", reqHeaders)
		} else {
			// Fallback
			w.Header().Set("Access-Control-Allow-Headers", "*")
		}

		// Expose all response headers
		w.Header().Set("Access-Control-Expose-Headers", "*")

		// Allow credentials (cookies, auth headers)
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		// Handle preflight request
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}
