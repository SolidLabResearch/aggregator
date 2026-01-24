package registration

import (
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
func handleProvisionFlow(w http.ResponseWriter, req model.RegistrationRequest, ownerWebID string, ownerToken string) {
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

	configCtx, configCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer configCancel()

	// Step 1: Fetch OIDC configuration from configured IDP
	// TODO: Cache this configuration
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

	// Step 2: Perform client_credentials grant using resolved client_id/client_secret
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

	// Step 3: Register RS at UMA authorization server (A4DS) if needed
	umaConfig, err := fetchUMAConfig(authorizationServer)
	if err != nil {
		logrus.WithError(err).Error("Unable to fetch UMA configuration")
		http.Error(w, "Unable to fetch UMA configuration", http.StatusInternalServerError)
		return
	}

	clientURI := fmt.Sprintf("%s://%s", model.Protocol, model.ExternalHost)
	rsClientID, rsClientSecret, pat, err := ensurePATForUMA(configCtx, umaConfig, tokenResp.AccessToken, clientURI)
	if err != nil {
		logrus.WithError(err).Error("Unable to obtain UMA protection API token")
		http.Error(w, "Unable to obtain UMA protection API token", http.StatusInternalServerError)
		return
	}

	if err := registerIngressUMAClient(authorizationServer, rsClientID, rsClientSecret, pat); err != nil {
		logrus.WithError(err).Error("Failed to register UMA client with ingress")
		http.Error(w, "Failed to register UMA client with ingress", http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	namespace, err := createNamespaceForAggregator(ownerWebID, authorizationServer, ctx)
	if err != nil {
		logrus.WithError(err).Error("Failed to create namespace")
		http.Error(w, "Failed to create namespace", http.StatusInternalServerError)
		return
	}

	tokenExpiry := ""
	if tokenResp.ExpiresIn > 0 {
		tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second).UTC().Format(time.RFC3339)
	}

	if err := deployAggregatorResources(namespace, oidcConfig.TokenEndpoint, tokenResp.AccessToken, tokenResp.RefreshToken, tokenExpiry, ownerWebID, ownerToken, authorizationServer, req.RegistrationType, webID, ctx); err != nil {
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
		Subject:      webID,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logrus.WithError(err).Error("Failed to write response")
	}
}
