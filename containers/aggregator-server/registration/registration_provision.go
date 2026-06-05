package registration

import (
	"aggregator/instance"
	"aggregator/model"
	"aggregator/oidc"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

// handleProvisionFlow handles the provision registration type
func handleProvisionFlow(w http.ResponseWriter, req model.RegistrationRequest) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Check if this is an update (aggregator_id provided)
	isUpdate := req.AggregatorID != ""

	if isUpdate {
		http.Error(w, "provision updates are not supported", http.StatusBadRequest)
		return
	}

	// Get OIDC Configuration
	oidcConfig, err := oidc.FetchOIDCConfig(ctx, model.OIDCServer)
	if err != nil {
		logrus.WithError(err).Warnf("Unable to fetch OIDC configuration for %s", model.OIDCServer)
		http.Error(w, "Authorization failed", http.StatusInternalServerError)
		return
	}
	// Get Client Registration Endpoint
	if oidcConfig.RegistrationEndpoint == "" {
		logrus.Warn("Missing registration endpoint in OIDC config")
		http.Error(w, "Authorization failed", http.StatusInternalServerError)
		return
	}
	logrus.Debugf("OIDC Registration Endpoint: %s", oidcConfig.RegistrationEndpoint)

	// Register new client
	aggregatorID, clientID, _, err := registerAggregatorClient(ctx, oidcConfig, nil)
	if err != nil {
		logrus.WithError(err).Error("Client registration failed")
		http.Error(w, "Failed to register client with IDP", http.StatusInternalServerError)
		return
	}
	logrus.Infof("Registered new client with IDP: %s (client_id: %s)", aggregatorID, clientID)

	// Store aggregator client tokens?

	// Deploy new aggregator instance
	err = instance.DeployAggregator(
		req.Party,
		aggregatorID,
		req.AuthorizationServer,
		ctx,
	)
	if err != nil {
		logrus.WithError(err).Error("Failed to deploy aggregator")
		http.Error(w, "Failed to deploy aggregator", http.StatusInternalServerError)
		return
	}

	inst := instance.CreateAggregatorInstanceRecord(
		req.Party,
		"provision",
		req.AuthorizationServer,
		aggregatorID,
	)

	logrus.Infof("Aggregator created (provision): %s with ID %s (acting for %s)", inst.AggregatorID, clientID, req.Party)

	response := model.RegistrationResponse{
		AggregatorID: inst.AggregatorID,
		Aggregator:   inst.BaseURL,
		Subject:      clientID,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logrus.WithError(err).Error("Failed to write response")
	}
}
