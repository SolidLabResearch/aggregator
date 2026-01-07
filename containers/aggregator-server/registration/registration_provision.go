package registration

import (
	"aggregator/model"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/sirupsen/logrus"
)

// handleProvisionFlow handles the provision registration type
func handleProvisionFlow(w http.ResponseWriter, req model.RegistrationRequest, ownerWebID string) {
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

	if authorizationServer == "" || webID == "" || clientID == "" || clientSecret == "" {
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
		clientID,
		clientSecret,
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

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
	}
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

	namespace, err := createNamespaceForAggregator(webID, authorizationServer, ctx)
	if err != nil {
		logrus.WithError(err).Error("Failed to create namespace")
		http.Error(w, "Failed to create namespace", http.StatusInternalServerError)
		return
	}

	if err := deployAggregatorResources(namespace, oidcConfig.TokenEndpoint, tokenResp.RefreshToken, webID, authorizationServer, ctx); err != nil {
		logrus.WithError(err).Error("Failed to deploy aggregator")
		http.Error(w, "Failed to deploy aggregator", http.StatusInternalServerError)
		return
	}

	instance := createAggregatorInstanceRecord(
		ownerWebID,
		"provision",
		authorizationServer,
		namespace,
		tokenResp.AccessToken,
		tokenResp.RefreshToken,
	)

	logrus.Infof("Aggregator created (provision): %s for WebID %s (acting as %s)", instance.AggregatorID, ownerWebID, webID)

	response := model.RegistrationResponse{
		AggregatorID: instance.AggregatorID,
		Aggregator:   instance.BaseURL,
		WebID:        webID,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logrus.WithError(err).Error("Failed to write response")
	}
}
