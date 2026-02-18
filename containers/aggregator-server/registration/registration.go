package registration

import (
	"aggregator/instance"
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

	switch registrationType {
	case "device_code":
		handleDeviceCodeFlow(w, req)
	case "none":
		handleNoneFlow(w, req)
	default:
		issuer, id, mode, err := authenticateRequest(r)
		if err != nil {
			logrus.WithError(err).Warn("Authentication failed")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if id == "" {
			logrus.Warn("Authentication missing for registration request")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Route to appropriate handler based on registration_type
		switch registrationType {
		case "provision":
			handleProvisionFlow(w, req, id)
		case "authorization_code":
			handleAuthorizationCodeFlow(w, req, issuer, id, mode)
		case "client_credentials":
			handleClientCredentialsFlow(w, req, issuer, id)
		default:
			logrus.Warnf("Unsupported registration_type: %s", registrationType)
			http.Error(w, "Unsupported registration_type", http.StatusBadRequest)
		}
	}
}

// handleRegistrationDelete handles DELETE requests for removing aggregators
func handleRegistrationDelete(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Parse request body
	var req struct {
		AggregatorID string `json:"aggregator_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logrus.WithError(err).Warn("Delete request failed: invalid JSON body")
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	logrus.Infof("Received delete request for aggregator: %s", req.AggregatorID)

	if req.AggregatorID == "" {
		logrus.Warn("Delete request missing aggregator_id")
		http.Error(w, "aggregator_id is required", http.StatusBadRequest)
		return
	}

	// Get aggregator instance
	inst, err := instance.GetAggregatorInstance(req.AggregatorID)
	if err != nil {
		logrus.WithError(err).Warnf("Aggregator not found: %s", req.AggregatorID)
		http.Error(w, "Aggregator not found", http.StatusNotFound)
		return
	}
	logrus.Debugf("Aggregator instance retrieved: %s (registration type: %s)", req.AggregatorID, inst.RegistrationType)

	// Authentication for non-none types
	if inst.RegistrationType != "none" {
		logrus.Debug("Authentication required for delete request")
		_, id, _, err := authenticateRequest(r)
		if err != nil {
			logrus.WithError(err).Warn("Authentication failed")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if id == "" {
			logrus.Warn("Authentication missing for delete request")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if !inst.HasOwnership(id) {
			logrus.WithField("requester", id).Warnf("Ownership check failed for aggregator %s", req.AggregatorID)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		logrus.Debugf("Ownership verified for aggregator %s by user %s", req.AggregatorID, id)
	} else {
		logrus.Debug("No authentication required for 'none' registration type")
	}

	// Delete Kubernetes resources
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	logrus.Infof("Deleting Kubernetes resources for aggregator: %s", req.AggregatorID)
	if err := instance.DeleteAggregator(inst.AggregatorID, ctx); err != nil {
		logrus.WithError(err).Errorf("Failed to delete Kubernetes resources for aggregator %s", req.AggregatorID)
		http.Error(w, "Failed to delete aggregator resources", http.StatusInternalServerError)
		return
	}
	logrus.Infof("Kubernetes resources deleted for aggregator: %s", req.AggregatorID)

	// Delete from storage
	logrus.Infof("Deleting aggregator instance from storage: %s", req.AggregatorID)
	if err := instance.DeleteAggregatorInstance(req.AggregatorID); err != nil {
		logrus.WithError(err).Errorf("Failed to delete aggregator from storage: %s", req.AggregatorID)
		http.Error(w, "Failed to delete aggregator", http.StatusInternalServerError)
		return
	}
	logrus.Infof("Aggregator deleted from storage: %s", req.AggregatorID)

	duration := time.Since(start)
	logrus.Infof("Aggregator deletion completed successfully: %s (took %s)", req.AggregatorID, duration)
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
