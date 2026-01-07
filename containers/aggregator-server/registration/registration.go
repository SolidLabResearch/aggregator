package registration

import (
	"aggregator/model"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// RegistrationHandler handles POST and DELETE requests to the registration endpoint
func RegistrationHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		handleRegistrationPost(w, r)
	case http.MethodDelete:
		handleRegistrationDelete(w, r)
	default:
		logrus.Warnf("Registration attempt with wrong method: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleRegistrationPost handles POST requests for creating/updating aggregators
func handleRegistrationPost(w http.ResponseWriter, r *http.Request) {
	// Authentication required
	ownerWebID, err := authenticateRequest(r)
	if err != nil {
		logrus.WithError(err).Warn("Authentication failed")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse request body
	var req model.RegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logrus.WithError(err).Warn("Invalid JSON body")
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	// Validate registration_type is present
	if req.RegistrationType == "" {
		logrus.Warn("Missing registration_type")
		http.Error(w, "registration_type is required", http.StatusBadRequest)
		return
	}

	registrationType := strings.ToLower(req.RegistrationType)
	if !isRegistrationTypeAllowed(registrationType) {
		logrus.Warnf("Registration type not allowed: %s", registrationType)
		http.Error(w, "Unsupported registration_type", http.StatusBadRequest)
		return
	}

	// Route to appropriate handler based on registration_type
	switch registrationType {
	case "provision":
		handleProvisionFlow(w, req, ownerWebID)
	case "authorization_code":
		handleAuthorizationCodeFlow(w, req, ownerWebID)
	case "client_credentials":
		handleClientCredentialsFlow(w, req, ownerWebID)
	case "device_code":
		http.Error(w, "device_code flow not yet implemented", http.StatusNotImplemented)
	default:
		logrus.Warnf("Unsupported registration_type: %s", registrationType)
		http.Error(w, "Unsupported registration_type", http.StatusBadRequest)
	}
}

// handleRegistrationDelete handles DELETE requests for removing aggregators
func handleRegistrationDelete(w http.ResponseWriter, r *http.Request) {
	// Authentication required
	ownerWebID, err := authenticateRequest(r)
	if err != nil {
		logrus.WithError(err).Warn("Authentication failed")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse request body
	var req struct {
		AggregatorID string `json:"aggregator_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logrus.WithError(err).Warn("Invalid JSON body")
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if req.AggregatorID == "" {
		http.Error(w, "aggregator_id is required", http.StatusBadRequest)
		return
	}

	// Check ownership
	if err := checkOwnership(req.AggregatorID, ownerWebID); err != nil {
		logrus.WithError(err).Warnf("Ownership check failed for aggregator %s", req.AggregatorID)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Get instance to clean up resources
	instance, err := getAggregatorInstance(req.AggregatorID)
	if err != nil {
		http.Error(w, "Aggregator not found", http.StatusNotFound)
		return
	}

	// Delete Kubernetes resources
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := deleteNamespaceResources(instance.Namespace, ctx); err != nil {
		logrus.WithError(err).Errorf("Failed to delete namespace resources for aggregator %s", req.AggregatorID)
		http.Error(w, "Failed to delete aggregator resources", http.StatusInternalServerError)
		return
	}

	// Delete from storage
	if err := deleteAggregatorInstance(req.AggregatorID); err != nil {
		logrus.WithError(err).Errorf("Failed to delete aggregator from storage: %s", req.AggregatorID)
		http.Error(w, "Failed to delete aggregator", http.StatusInternalServerError)
		return
	}

	logrus.Infof("Aggregator deleted successfully: %s", req.AggregatorID)
	w.WriteHeader(http.StatusNoContent)
}

func isRegistrationTypeAllowed(registrationType string) bool {
	if len(model.AllowedRegistrationTypes) == 0 {
		return true
	}

	for _, allowed := range model.AllowedRegistrationTypes {
		if registrationType == allowed {
			return true
		}
	}

	return false
}
