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

// handleClientCredentialsFlow handles the client_credentials registration type
func handleClientCredentialsFlow(w http.ResponseWriter, req model.RegistrationRequest, ownerWebID string, idpIssuer string, ownerToken string) {
	// Check if this is an update
	isUpdate := req.AggregatorID != ""

	if isUpdate {
		// Verify ownership
		if err := checkOwnership(req.AggregatorID, ownerWebID); err != nil {
			http.Error(w, "Forbidden", http.StatusForbidden)
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
	if idpIssuer == "" {
		http.Error(w, "issuer is required", http.StatusBadRequest)
		return
	}

	// Step 1: Fetch OIDC configuration
	oidcConfig, err := fetchOIDCConfig(idpIssuer)
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
	tokenData.Set("webid", ownerWebID)

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

	// Validate that we got tokens
	if tokenResp.AccessToken == "" {
		logrus.Error("Token response missing access_token")
		http.Error(w, "Invalid token response: missing access_token", http.StatusInternalServerError)
		return
	}

	if !isUpdate && strings.TrimSpace(req.AuthorizationServer) != "" {
		configCtx, configCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer configCancel()

		umaConfig, err := fetchUMAConfig(req.AuthorizationServer)
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

		if err := registerIngressUMAClient(req.AuthorizationServer, rsClientID, rsClientSecret, pat); err != nil {
			logrus.WithError(err).Error("Failed to register UMA client with ingress")
			http.Error(w, "Failed to register UMA client with ingress", http.StatusInternalServerError)
			return
		}
	}

	tokenExpiry := ""
	if tokenResp.ExpiresIn > 0 {
		tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second).UTC().Format(time.RFC3339)
	}

	var instance *model.AggregatorInstance
	if isUpdate {
		// Update existing aggregator tokens
		if err := updateAggregatorInstanceTokens(req.AggregatorID, tokenResp.AccessToken, tokenResp.RefreshToken); err != nil {
			logrus.WithError(err).Errorf("Failed to update aggregator tokens: %s", req.AggregatorID)
			http.Error(w, "Failed to update aggregator", http.StatusInternalServerError)
			return
		}
		instance, _ = getAggregatorInstance(req.AggregatorID)
		if instance != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := updateAggregatorInstanceDeployments(instance.Namespace, tokenResp.AccessToken, tokenResp.RefreshToken, tokenExpiry, ownerToken, ctx); err != nil {
				logrus.WithError(err).Errorf("Failed to update aggregator deployments: %s", req.AggregatorID)
				http.Error(w, "Failed to update aggregator", http.StatusInternalServerError)
				return
			}
		}
		logrus.Infof("Aggregator tokens updated (client_credentials): %s", req.AggregatorID)
	} else {
		// Create new aggregator instance
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Create namespace for the aggregator
		namespace, err := createNamespaceForAggregator(ownerWebID, req.AuthorizationServer, ctx)
		if err != nil {
			logrus.WithError(err).Error("Failed to create namespace")
			http.Error(w, "Failed to create namespace", http.StatusInternalServerError)
			return
		}

		// Deploy aggregator resources
		if err := deployAggregatorResources(namespace, oidcConfig.TokenEndpoint, tokenResp.AccessToken, tokenResp.RefreshToken, tokenExpiry, ownerWebID, ownerToken, req.AuthorizationServer, req.RegistrationType, "", ctx); err != nil {
			logrus.WithError(err).Error("Failed to deploy aggregator")
			http.Error(w, "Failed to deploy aggregator", http.StatusInternalServerError)
			return
		}

		// Create aggregator record
		instance = createAggregatorInstanceRecord(
			ownerWebID,
			"client_credentials",
			req.AuthorizationServer,
			namespace,
			tokenResp.AccessToken,
			tokenResp.RefreshToken,
		)

		logrus.Infof("Aggregator created (client_credentials): %s for WebID %s", instance.AggregatorID, ownerWebID)
	}

	// Return response
	response := model.RegistrationResponse{
		AggregatorID: instance.AggregatorID,
		Aggregator:   instance.BaseURL,
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
