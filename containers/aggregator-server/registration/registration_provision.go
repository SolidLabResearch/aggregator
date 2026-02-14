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
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// handleProvisionFlow handles the provision registration type
func handleProvisionFlow(w http.ResponseWriter, req model.RegistrationRequest, id string) {
	// Check if this is an update (aggregator_id provided)
	isUpdate := req.AggregatorID != ""

	if isUpdate {
		http.Error(w, "provision updates are not supported", http.StatusBadRequest)
		return
	}

	authorizationServer := model.ProvisionAuthorizationServer
	webID := model.ProvisionWebID
	clientID := model.ProvisionClientID
	clientSecret := model.ProvisionClientSecret
	idpIssuer := model.ProvisionIDP

	if authorizationServer == "" || webID == "" || clientID == "" || clientSecret == "" || idpIssuer == "" {
		http.Error(w, "Provisioning configuration is not set", http.StatusInternalServerError)
		return
	}

	// Step 1: Discover IDP from the target WebID
	idpIssuer, err := discoverIDPFromWebID(webID)
	if err != nil {
		logrus.WithError(err).Errorf("Failed to discover IDP from WebID: %s", webID)
		http.Error(w, "Failed to discover IDP from WebID", http.StatusInternalServerError)
		return
	}

	// Step 2: Fetch OIDC configuration
	oidcConfig, err := fetchOIDCConfig(idpIssuer)
	if err != nil {
		logrus.WithError(err).Error("Unable to fetch OIDC configuration")
		http.Error(w, "Unable to fetch OIDC configuration", http.StatusInternalServerError)
		return
	}

	clientIDToUse := clientID
	clientSecretToUse := clientSecret
	if strings.EqualFold(model.IDPServerType, "solid") &&
		strings.Contains(clientID, "@") && !strings.HasPrefix(clientID, "http") {
		baseURL, err := deriveSolidBaseURL(idpIssuer)
		if err != nil {
			logrus.WithError(err).Error("Unable to determine Solid base URL")
			http.Error(w, "Unable to determine Solid base URL", http.StatusInternalServerError)
			return
		}
		solidClientID, solidClientSecret, err := fetchSolidClientCredentials(baseURL, clientID, clientSecret, "aggregator-provision", webID)
		if err != nil {
			logrus.WithError(err).Error("Unable to obtain Solid client credentials")
			http.Error(w, "Unable to obtain Solid client credentials", http.StatusInternalServerError)
			return
		}
		clientIDToUse = solidClientID
		clientSecretToUse = solidClientSecret
	}

	// Step 3: Perform client_credentials grant using configured client_id/client_secret
	tokenData := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"openid webid offline_access"},
	}
	tokenData.Set("webid", webID)

	resp, err := doTokenRequest(
		oidcConfig.TokenEndpoint,
		oidcConfig.TokenEndpointAuthMethodsSupported,
		tokenData,
		clientIDToUse,
		clientSecretToUse,
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

		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		http.Error(w, fmt.Sprintf("Token endpoint error: %s", string(body)), http.StatusBadGateway)
		return
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		logrus.WithError(err).Error("Failed to parse token response")
		http.Error(w, "Invalid token response", http.StatusInternalServerError)
		return
	}

	if tokenResp.AccessToken == "" {
		logrus.Error("Token response missing access_token")
		http.Error(w, "Invalid token response: missing access_token", http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Store user tokens
	err = storeTokens(id, tokenResp)
	if err != nil {
		logrus.WithError(err).Error("Failed to store user tokens")
		http.Error(w, "Failed to store user tokens", http.StatusInternalServerError)
		return
	}

	aggregatorId, err := instance.DeployAggregator(
		webID,
		authorizationServer,
		ctx,
	)
	if err != nil {
		logrus.WithError(err).Error("Failed to deploy aggregator")
		http.Error(w, "Failed to deploy aggregator", http.StatusInternalServerError)
		return
	}

	inst := instance.CreateAggregatorInstanceRecord(
		id,
		"provision",
		authorizationServer,
		aggregatorId,
	)

	logrus.Infof("Aggregator created (provision): %s for ID %s (acting as %s)", inst.AggregatorID, id, webID)

	response := model.RegistrationResponse{
		AggregatorID: inst.AggregatorID,
		Aggregator:   inst.BaseURL,
		Subject:      webID,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logrus.WithError(err).Error("Failed to write response")
	}
}
