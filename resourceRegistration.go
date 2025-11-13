package main

import (
	"aggregator/auth"
	"context"
	"encoding/json"
	"fmt"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"net/http"
	"os"
	"time"
)

const resourceSubscriptionPort = "4449"

type Source struct {
	Issuer               string `json:"issuer"`
	DerivationResourceID string `json:"derivation_resource_id"`
}

// ResourceRegistration represents the data sent by pods to register their endpoints
type ResourceRegistration struct {
	PodName     string               `json:"pod_name"`
	PodIP       string               `json:"pod_ip"`
	Port        int                  `json:"port"`
	Endpoint    string               `json:"endpoint"`
	Scopes      []auth.ResourceScope `json:"scopes"`
	Description string               `json:"description"`
	Sources     []Source             `json:"sources,omitempty"`
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

	externalUrl := fmt.Sprintf("%s://%s:%s/%s%s", Protocol, Host, ServerPort, actorID, registration.Endpoint)

	for _, scope := range registration.Scopes {
		if scope == auth.ScopeContinuousRead ||
			scope == auth.ScopeContinuousWrite ||
			scope == auth.ScopeContinuousDuplex {
			auth.AddStreamingResource(externalUrl, scope)
		}
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
		"external_url": externalUrl,
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

	// Default endpoint to "/" if not specified for lookup
	endpoint := updateInfo.Endpoint
	if endpoint == "" {
		endpoint = "/"
	}

	logrus.WithFields(logrus.Fields{"pod": actorID, "endpoint": endpoint}).Info("📋 Processing update")

	// Update the registration (partial merge)
	resourceKey := fmt.Sprintf("%s%s", actorID, endpoint)
	existing, exists := registeredResources[resourceKey]
	if !exists {
		logrus.WithFields(logrus.Fields{"endpoint": endpoint, "pod": actorID}).Warn("❌ Resource not found for pod")
		http.Error(w, "Resource not found", http.StatusNotFound)
		return
	}

	// Merge only provided non-zero fields
	if updateInfo.PodIP != "" {
		existing.PodIP = updateInfo.PodIP
	}
	if updateInfo.Port != 0 {
		existing.Port = updateInfo.Port
	}
	if updateInfo.Endpoint != "" && updateInfo.Endpoint != existing.Endpoint {
		// Re-key if endpoint changed
		newKey := fmt.Sprintf("%s%s", actorID, updateInfo.Endpoint)
		registeredResources[newKey] = existing
		existing.Endpoint = updateInfo.Endpoint
		delete(registeredResources, resourceKey)
		resourceKey = newKey
	}
	if len(updateInfo.Scopes) > 0 {
		existing.Scopes = updateInfo.Scopes
		// Update streaming resource if relevant
		externalUrl := fmt.Sprintf("%s://%s:%s/%s%s", Protocol, Host, ServerPort, actorID, existing.Endpoint)
		for _, scope := range updateInfo.Scopes {
			if scope == auth.ScopeContinuousRead || scope == auth.ScopeContinuousWrite || scope == auth.ScopeContinuousDuplex {
				auth.AddStreamingResource(externalUrl, scope)
			}
		}
	}
	if updateInfo.Description != "" {
		existing.Description = updateInfo.Description
	}
	if updateInfo.Sources != nil && len(updateInfo.Sources) > 0 {
		existing.Sources = updateInfo.Sources
	}

	// Update UMA resource to reflect new scopes and relations
	resourceID := fmt.Sprintf("%s://%s:%s/%s%s", Protocol, Host, ServerPort, actorID, existing.Endpoint)
	var resourceRelations interface{}
	if len(existing.Sources) > 0 {
		resourceRelations = map[string][]Source{
			"prov:wasDerivedFrom": existing.Sources,
		}
	}
	if err := auth.CreateResource(resourceID, existing.Scopes, resourceRelations); err != nil {
		logrus.WithFields(logrus.Fields{"resource_id": resourceID, "err": err}).Error("❌ Failed to update UMA resource")
		// Do not fail the update; continue
	}

	logrus.WithFields(logrus.Fields{"endpoint": existing.Endpoint, "pod": actorID}).Info("✅ Resource updated")

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

	// Create the resource ID - this should match the external URL pattern
	resourceID := fmt.Sprintf("%s://%s:%s/%s%s", Protocol, Host, ServerPort, actorID, registration.Endpoint)

	// Build resource relations from sources if provided
	var resourceRelations interface{}
	if len(registration.Sources) > 0 {
		resourceRelations = map[string][]Source{
			"prov:wasDerivedFrom": registration.Sources,
		}
	}

	// Register or update the resource with UMA
	if err := auth.CreateResource(resourceID, registration.Scopes, resourceRelations); err != nil {
		return fmt.Errorf("failed to create UMA resource: %v", err)
	}

	logrus.WithFields(logrus.Fields{"actor_id": actorID, "scopes": registration.Scopes}).Info("✅ Successfully registered resource with UMA")
	return nil
}
