package main

import (
	"aggregator/auth"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const resourceSubscriptionPort = "4449"

// ResourceRegistration represents the data sent by pods to register their endpoints
type ResourceRegistration struct {
	PodName     string   `json:"pod_name"`
	PodIP       string   `json:"pod_ip"`
	Port        int      `json:"port"`
	Endpoint    string   `json:"endpoint"`
	Scopes      []string `json:"scopes"`
	Description string   `json:"description"`
}

var registeredResources = make(map[string]*ResourceRegistration)

func SetupResourceRegistration() {
	// Create a separate mux for the registration server
	registrationMux := http.NewServeMux()
	registrationMux.HandleFunc("/", handleResourceOperations)

	logrus.WithFields(logrus.Fields{"port": resourceSubscriptionPort}).Info("🚀 Resource Registration server starting")
	logrus.Info("🔗 Resource endpoints")
	logrus.WithFields(logrus.Fields{"method": "PUT", "url": fmt.Sprintf("http://aggregator-registration:%s/", resourceSubscriptionPort), "description": "Create/update resource"}).Info("Resource endpoint")
	logrus.WithFields(logrus.Fields{"method": "POST", "url": fmt.Sprintf("http://aggregator-registration:%s/", resourceSubscriptionPort), "description": "Create resource"}).Info("Resource endpoint")
	logrus.WithFields(logrus.Fields{"method": "PATCH", "url": fmt.Sprintf("http://aggregator-registration:%s/", resourceSubscriptionPort), "description": "Update resource"}).Info("Resource endpoint")
	logrus.WithFields(logrus.Fields{"method": "DELETE", "url": fmt.Sprintf("http://aggregator-registration:%s/", resourceSubscriptionPort), "description": "Delete resource"}).Info("Resource endpoint")

	// Start the registration server with its own mux
	go func() {
		server := &http.Server{
			Addr:    "0.0.0.0:" + resourceSubscriptionPort,
			Handler: registrationMux,
		}
		if err := server.ListenAndServe(); err != nil {
			logrus.WithFields(logrus.Fields{"err": err}).Error("Failed to start resource registration server")
			os.Exit(1)
		}
	}()
}

func handleResourceOperations(w http.ResponseWriter, r *http.Request) {
	logrus.WithFields(logrus.Fields{"remote_addr": r.RemoteAddr, "method": r.Method}).Info("📥 Received resource registration request")

	switch r.Method {
	case http.MethodPost, http.MethodPut:
		handleResourceRegistration(w, r)
	case http.MethodPatch:
		handleResourceUpdate(w, r)
	case http.MethodDelete:
		handleResourceDeletion(w, r)
	default:
		logrus.WithFields(logrus.Fields{"method": r.Method}).Warn("❌ Invalid method for resource registration")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleResourceRegistration(w http.ResponseWriter, r *http.Request) {
	logrus.WithFields(logrus.Fields{"method": r.Method, "remote_addr": r.RemoteAddr}).Info("📝 Processing resource registration")

	var registration ResourceRegistration
	if err := json.NewDecoder(r.Body).Decode(&registration); err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("❌ Failed to decode registration JSON")
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	// Extract actorID from pod_name
	actorID := registration.PodName
	if actorID == "" {
		logrus.Warn("❌ Missing pod_name in registration")
		http.Error(w, "Missing required field: pod_name", http.StatusBadRequest)
		return
	}

	logrus.WithFields(logrus.Fields{"pod": actorID, "pod_ip": registration.PodIP, "port": registration.Port, "endpoint": registration.Endpoint, "scopes": registration.Scopes}).Info("📋 Processing registration")

	// Default endpoint to "/" if not specified
	if registration.Endpoint == "" {
		registration.Endpoint = "/"
	}

	// Validate required fields
	if registration.PodIP == "" || registration.Port == 0 {
		logrus.WithFields(logrus.Fields{"pod_ip": registration.PodIP, "port": registration.Port}).Warn("❌ Missing required fields in registration")
		http.Error(w, "Missing required fields: pod_ip, port", http.StatusBadRequest)
		return
	}

	if len(registration.Scopes) == 0 {
		logrus.WithFields(logrus.Fields{"pod": actorID}).Warn("❌ No scopes provided for resource")
		http.Error(w, "Scopes are required", http.StatusBadRequest)
		return
	}

	// Store the registration
	resourceKey := fmt.Sprintf("%s%s", actorID, registration.Endpoint)

	// Check if this is an update (PUT) or creation (POST)
	isUpdate := false
	if _, exists := registeredResources[resourceKey]; exists && r.Method == "PUT" {
		isUpdate = true
	} else if _, exists := registeredResources[resourceKey]; exists && r.Method == "POST" {
		logrus.WithFields(logrus.Fields{"endpoint": registration.Endpoint, "pod": actorID}).Warn("❌ Resource already exists for pod")
		http.Error(w, "Resource already exists, use PUT to update", http.StatusConflict)
		return
	}

	registeredResources[resourceKey] = &registration

	// Create Kubernetes service for the pod (only if new registration)
	if !isUpdate {
		if err := setupServiceForResource(actorID, &registration); err != nil {
			logrus.WithFields(logrus.Fields{"pod": actorID, "err": err}).Error("❌ Failed to setup service")
			// Continue anyway
		}

		// Register resource with UMA Authorization Server (only if new registration)
		if err := registerResourceWithUMA(actorID, &registration); err != nil {
			logrus.WithFields(logrus.Fields{"pod": actorID, "err": err}).Error("❌ Failed to register resource with UMA")
			// Continue anyway - the service is still functional
		}
	}

	action := "registered"
	if isUpdate {
		action = "updated"
	}
	logrus.WithFields(logrus.Fields{"action": action, "endpoint": registration.Endpoint, "pod": actorID}).Info("🎉 Resource registration success")

	response := map[string]interface{}{
		"status":       "success",
		"message":      fmt.Sprintf("Resource %s successfully", action),
		"external_url": fmt.Sprintf("%s://%s:%s/%s%s", Protocol, ExternalHost, ExternalPort, actorID, registration.Endpoint),
		"actor_id":     actorID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleResourceUpdate(w http.ResponseWriter, r *http.Request) {
	logrus.WithFields(logrus.Fields{"remote_addr": r.RemoteAddr}).Info("✏️ Received resource update request")

	var updateInfo ResourceRegistration
	if err := json.NewDecoder(r.Body).Decode(&updateInfo); err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("❌ Failed to decode update JSON")
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	// Extract actorID from pod_name
	actorID := updateInfo.PodName
	if actorID == "" {
		logrus.Warn("❌ Missing pod_name in update request")
		http.Error(w, "Missing required field: pod_name", http.StatusBadRequest)
		return
	}

	logrus.WithFields(logrus.Fields{"pod": actorID, "endpoint": updateInfo.Endpoint}).Info("📋 Processing update")

	// Update the registration
	resourceKey := fmt.Sprintf("%s%s", actorID, updateInfo.Endpoint)
	if _, exists := registeredResources[resourceKey]; !exists {
		logrus.WithFields(logrus.Fields{"endpoint": updateInfo.Endpoint, "pod": actorID}).Warn("❌ Resource not found for pod")
		http.Error(w, "Resource not found", http.StatusNotFound)
		return
	}

	// Update the resource registration
	registeredResources[resourceKey] = &updateInfo

	logrus.WithFields(logrus.Fields{"endpoint": updateInfo.Endpoint, "pod": actorID}).Info("✅ Resource updated")

	response := map[string]interface{}{
		"status":  "success",
		"message": "Resource updated successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleResourceDeletion(w http.ResponseWriter, r *http.Request) {
	logrus.WithFields(logrus.Fields{"remote_addr": r.RemoteAddr}).Info("🗑️ Received resource deletion request")

	var deletionInfo ResourceRegistration
	if err := json.NewDecoder(r.Body).Decode(&deletionInfo); err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("❌ Failed to decode deletion JSON")
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	// Extract actorID from pod_name
	actorID := deletionInfo.PodName
	if actorID == "" {
		logrus.Warn("❌ Missing pod_name in deletion request")
		http.Error(w, "Missing required field: pod_name", http.StatusBadRequest)
		return
	}

	logrus.WithFields(logrus.Fields{"pod": actorID, "endpoint": deletionInfo.Endpoint}).Info("📋 Processing deletion")

	// Delete the registration
	resourceKey := fmt.Sprintf("%s%s", actorID, deletionInfo.Endpoint)
	if _, exists := registeredResources[resourceKey]; !exists {
		logrus.WithFields(logrus.Fields{"endpoint": deletionInfo.Endpoint, "pod": actorID}).Warn("❌ Resource not found for pod")
		http.Error(w, "Resource not found", http.StatusNotFound)
		return
	}

	// Remove the resource registration
	delete(registeredResources, resourceKey)

	logrus.WithFields(logrus.Fields{"endpoint": deletionInfo.Endpoint, "pod": actorID}).Info("✅ Resource deleted")

	response := map[string]interface{}{
		"status":  "success",
		"message": "Resource deleted successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func setupServiceForResource(actorID string, registration *ResourceRegistration) error {
	logrus.WithFields(logrus.Fields{"actor_id": actorID}).Info("Creating Kubernetes service for actor")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serviceName := fmt.Sprintf("id%s-service", actorID)

	// Check if service already exists
	_, err := Clientset.CoreV1().Services("default").Get(ctx, serviceName, metav1.GetOptions{})
	if err == nil {
		logrus.WithFields(logrus.Fields{"service": serviceName}).Info("Service already exists")
		return nil
	}

	// Create new service
	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: serviceName,
			Labels: map[string]string{
				"app":       actorID,
				"component": "actor-service",
			},
		},
		Spec: v1.ServiceSpec{
			Selector: map[string]string{
				"app": actorID,
			},
			Ports: []v1.ServicePort{
				{
					Name:       "http",
					Port:       80,
					TargetPort: intstr.FromInt(registration.Port),
					Protocol:   v1.ProtocolTCP,
				},
			},
			Type: v1.ServiceTypeClusterIP,
		},
	}

	_, err = Clientset.CoreV1().Services("default").Create(ctx, service, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create service %s: %v", serviceName, err)
	}

	logrus.WithFields(logrus.Fields{"service": serviceName, "actor_id": actorID}).Info("Created Kubernetes service for actor")
	return nil
}

func registerResourceWithUMA(actorID string, registration *ResourceRegistration) error {
	logrus.WithFields(logrus.Fields{"actor_id": actorID}).Info("🔑 Registering resource with UMA")

	// Convert string scopes to auth.ResourceScope types
	resourceScopes := make([]auth.ResourceScope, 0, len(registration.Scopes))
	for _, scope := range registration.Scopes {
		switch strings.ToLower(scope) {
		case "read":
			resourceScopes = append(resourceScopes, auth.ScopeRead)
		case "write":
			resourceScopes = append(resourceScopes, auth.ScopeWrite)
		case "append":
			resourceScopes = append(resourceScopes, auth.ScopeAppend)
		case "create":
			resourceScopes = append(resourceScopes, auth.ScopeCreate)
		case "delete":
			resourceScopes = append(resourceScopes, auth.ScopeDelete)
		default:
			logrus.WithFields(logrus.Fields{"scope": scope, "actor_id": actorID}).Warn("⚠️ Unknown scope for resource scope entry skipped")
		}
	}

	if len(resourceScopes) == 0 {
		return fmt.Errorf("no valid UMA scopes found for resource %s", actorID)
	}

	// Create the resource ID - this should match the external URL pattern
	resourceID := fmt.Sprintf("%s://%s:%s/%s%s", Protocol, ExternalHost, ExternalPort, actorID, registration.Endpoint)

	// Register the resource with UMA
	if err := auth.CreateResource(resourceID, resourceScopes); err != nil {
		return fmt.Errorf("failed to create UMA resource: %v", err)
	}

	logrus.WithFields(logrus.Fields{"actor_id": actorID, "scopes": resourceScopes}).Info("✅ Successfully registered resource with UMA")
	return nil
}

// getHostIPForCluster gets the host IP address that's accessible from inside the cluster
func getHostIPForCluster() (string, error) {
	// For minikube, pods can reach the host via the gateway IP
	// For minikube, we need to get the host IP that's accessible from pods
	// This is typically the minikube VM's host-only adapter IP

	// Try to get the IP by connecting to a known external service
	// This will give us the local IP that would be used for outbound connections
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", fmt.Errorf("failed to get local IP: %v", err)
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	hostIP := localAddr.IP.String()

	logrus.WithFields(logrus.Fields{"host_ip": hostIP}).Info("🔍 Detected host IP accessible from cluster")
	return hostIP, nil
}
