package registration

import (
	"aggregator/instance"
	"aggregator/model"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// handleClientCredentialsFlow handles the client_credentials registration type
func handleClientCredentialsFlow(w http.ResponseWriter, req model.RegistrationRequest, issuer string, id string) {
	// Check if this is an update
	isUpdate := req.AggregatorID != ""

	var inst *instance.AggregatorInstance
	if isUpdate {
		// Check if aggregator exists and user is authorized to update it
		var err error
		inst, err = instance.GetAggregatorInstance(req.AggregatorID)
		if err != nil {
			logrus.WithError(err).Errorf("Failed to retrieve aggregator %s for update", req.AggregatorID)
			http.Error(w, "Aggregator not found for update", http.StatusNotFound)
			return
		}

		// Is user authorized to update this aggregator?
		if !inst.HasOwnership(id) {
			logrus.Errorf("User %s does not have ownership of the aggregator %s", id, req.AggregatorID)
			http.Error(w, "Not authorized to update this aggregator", http.StatusForbidden)
			return
		}
	}

	// Validate required fields
	if req.AuthorizationServer == "" {
		http.Error(w, "authorization_server is required", http.StatusBadRequest)
		return
	}
	if req.ClientID == "" {
		http.Error(w, "client_id is required", http.StatusBadRequest)
		return
	}
	if req.ClientSecret == "" {
		http.Error(w, "client_secret is required", http.StatusBadRequest)
		return
	}

	// Step 1: Fetch OIDC configuration
	oidcConfig, err := fetchOIDCConfig(issuer)
	if err != nil {
		logrus.WithError(err).Error("Unable to fetch OIDC configuration")
		http.Error(w, "Unable to fetch OIDC configuration", http.StatusInternalServerError)
		return
	}

	// Step 2: Perform client_credentials grant using provided client_id/client_secret
	tokenData := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"openid webid offline_access"},
	}

	// Some IDPs support a webid parameter to specify which WebID to act as
	if req.WebID != "" {
		tokenData.Set("webid", req.WebID)
	}

	resp, err := doTokenRequest(
		oidcConfig.TokenEndpoint,
		oidcConfig.TokenEndpointAuthMethodsSupported,
		tokenData,
		req.ClientID,
		req.ClientSecret,
	)
	if err != nil {
		logrus.WithError(err).Error("Token request failed")
		http.Error(w, "Failed to obtain tokens from IDP", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		logrus.Errorf("Token endpoint returned %d: %s", resp.StatusCode, string(body))

		// If client_credentials failed, it might be because credentials are invalid
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		http.Error(w, fmt.Sprintf("Token endpoint error: %s", string(body)), http.StatusBadGateway)
		return
	}

	// Parse token response
	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		logrus.WithError(err).Error("Failed to parse token response")
		http.Error(w, "Invalid token response", http.StatusInternalServerError)
		return
	}

	// Validate that we got tokens
	if tokenResp.AccessToken == "" {
		logrus.Error("Token response missing access_token")
		http.Error(w, "Invalid token response: missing access_token", http.StatusInternalServerError)
		return
	}

	if isUpdate {
		upsertTokens(id, tokenResp, issuer, req.ClientID, req.ClientSecret)
		logrus.Infof("Aggregator tokens updated (client_credentials): %s", req.AggregatorID)
	} else {
		// Store user tokens
		err = upsertTokens(id, tokenResp, issuer, req.ClientID, req.ClientSecret)
		if err != nil {
			logrus.WithError(err).Error("Failed to store user tokens")
			http.Error(w, "Failed to store user tokens", http.StatusInternalServerError)
			return
		}

		// Create new aggregator instance
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Deploy aggregator resources
		aggregatorID := uuid.New().String()
		err := instance.DeployAggregator(
			id,
			aggregatorID,
			req.AuthorizationServer,
			ctx,
		)
		if err != nil {
			logrus.WithError(err).Error("Failed to deploy aggregator")
			http.Error(w, "Failed to deploy aggregator", http.StatusInternalServerError)
			return
		}

		// Create aggregator record
		inst = instance.CreateAggregatorInstanceRecord(
			id,
			"client_credentials",
			req.AuthorizationServer,
			aggregatorID,
		)

		if req.WebID != "" {
			logrus.Infof("Aggregator created (client_credentials): %s for ID %s (acting as %s)", inst.AggregatorID, id, req.WebID)
		} else {
			logrus.Infof("Aggregator created (client_credentials): %s for ID %s", inst.AggregatorID, id)
		}
	}

	// Return response
	response := model.RegistrationResponse{
		AggregatorID: inst.AggregatorID,
		Aggregator:   inst.BaseURL,
		Subject:      id,
	}

	w.Header().Set("Content-Type", "application/json")
	if isUpdate {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusCreated)
	}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logrus.WithError(err).Error("Failed to write response")
	}
}
