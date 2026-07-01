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
	case http.MethodGet:
		handleRegistrationGet(w, r)
	case http.MethodPost:
		handleRegistrationPost(w, r)
	case http.MethodDelete:
		handleRegistrationDelete(w, r)
	default:
		logrus.Warnf("Registration attempt with wrong method: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleRegistrationGet handles GET requests for listing user aggregators
func handleRegistrationGet(w http.ResponseWriter, r *http.Request) {
	log := logrus.WithField("handler", "handleRegistrationGet")
	log.Info("Incoming list request")

	w.Header().Set("Content-Type", "application/json")

	// Check if Authorization header exists
	authHeader := r.Header.Get("Authorization")

	// CASE 1: No auth header → return public aggregators
	if authHeader == "" {
		publicInstances, err := instance.ListPublicAggregators()
		if err != nil {
			log.WithError(err).Error("Failed to list public aggregators")
			http.Error(w, "Failed to list public aggregators", http.StatusInternalServerError)
			return
		}

		log.Infof("No auth provided. Returning %d public aggregators", len(publicInstances))

		baseURLs := make([]string, 0, len(publicInstances))
		for _, inst := range publicInstances {
			baseURLs = append(baseURLs, inst.BaseURL)
		}

		json.NewEncoder(w).Encode(map[string][]string{
			"aggregators": baseURLs,
		})
		return
	}

	// CASE 2: Auth header exists → validate
	_, id, _, err := authenticateRequest(r)
	if err != nil || id == "" {
		log.WithError(err).Warn("Invalid authentication provided")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// CASE 3: Valid auth → return user aggregators
	instances, err := instance.ListAggregatorsByOwner(id)
	if err != nil {
		log.WithError(err).Error("Failed to list aggregators")
		http.Error(w, "Failed to list aggregators", http.StatusInternalServerError)
		return
	}

	log.Infof("Found %d aggregators for user %s", len(instances), id)

	baseURLs := make([]string, 0, len(instances))
	for _, inst := range instances {
		baseURLs = append(baseURLs, inst.BaseURL)
	}

	json.NewEncoder(w).Encode(map[string][]string{
		"aggregators": baseURLs,
	})
}

// handleRegistrationPost handles POST requests for creating/updating aggregators
func handleRegistrationPost(w http.ResponseWriter, r *http.Request) {
	log := logrus.WithField("handler", "handleRegistrationPost")
	log.Info("Incoming registration request")

	// Parse request body
	var req model.RegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.WithError(err).
			WithField("stage", "decode_body").
			Warn("Failed to decode JSON body")
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	log.Debug("Request body successfully decoded")

	// Validate registration_type
	if req.RegistrationType == "" {
		log.WithField("stage", "validation").
			Warn("Missing registration_type")
		http.Error(w, "registration_type is required", http.StatusBadRequest)
		return
	}

	registrationType := strings.ToLower(req.RegistrationType)
	log = log.WithField("registration_type", registrationType)

	if !isRegistrationTypeAllowed(registrationType) {
		log.WithField("stage", "validation").
			Warn("Unsupported registration_type")
		http.Error(w, "Unsupported registration_type", http.StatusBadRequest)
		return
	}
	log.Debug("registration_type validated")

	// Public flows (no auth required)
	switch registrationType {
	case "device_code":
		log.Info("Routing to device_code flow")
		handleDeviceCodeFlow(w, req)
		return

	case "none":
		log.Info("Routing to none flow")
		handleNoneFlow(w, req)
		return
	}

	// Authentication required for remaining flows
	log.Debug("Authenticating request")
	issuer, id, mode, err := authenticateRequest(r)
	if err != nil {
		log.WithError(err).
			WithField("stage", "authentication").
			Warn("Authentication failed")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if id == "" {
		log.WithField("stage", "authentication").
			Warn("Missing subject identifier in authentication")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	log = log.WithFields(logrus.Fields{
		"issuer":    issuer,
		"client_id": id,
		"auth_mode": mode,
	})
	log.Debug("Authentication successful")

	// Route to authenticated flows
	switch registrationType {
	case "token_exchange":
		log.Info("Routing to token_exchange flow")
		subjectToken, err := extractBearerToken(r)
		if err != nil {
			log.WithError(err).Warn("Failed to extract subject token from Authorization header")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		handleTokenExchangeFlow(w, req, subjectToken)
	case "provision":
		log.Info("Routing to provision flow")
		handleProvisionFlow(w, req, id)

	case "authorization_code":
		log.Info("Routing to authorization_code flow")
		handleAuthorizationCodeFlow(w, req, issuer, id, mode)

	case "client_credentials":
		log.Info("Routing to client_credentials flow")
		handleClientCredentialsFlow(w, req, issuer, id)

	default:
		log.WithField("stage", "routing").
			Warn("Reached unexpected registration_type")
		http.Error(w, "Unsupported registration_type", http.StatusBadRequest)
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

	// Delete user tokens
	if inst.RegistrationType != "none" {
		deleteTokens(inst.OwnerID)
	}

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
