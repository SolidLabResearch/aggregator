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

	"github.com/sirupsen/logrus"
)

// handleAuthorizationCodeFlow handles the authorization_code registration type
func handleAuthorizationCodeFlow(w http.ResponseWriter, req model.RegistrationRequest, issuer string, id string, mode string) {
	// Check if this is start or finish phase
	if req.Code == "" {
		// Start phase
		handleAuthorizationCodeStart(w, req, issuer, id, mode)
	} else {
		// Finish phase
		handleAuthorizationCodeFinish(w, req, id, mode)
	}
}

// handleAuthorizationCodeStart handles the start phase of authorization_code flow
func handleAuthorizationCodeStart(w http.ResponseWriter, req model.RegistrationRequest, issuer string, id string, mode string) {
	// Check if this is an update
	isUpdate := req.AggregatorID != ""

	if isUpdate {
		// Check if aggregator exists and user is authorized to update it
		inst, err := instance.GetAggregatorInstance(req.AggregatorID)
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
	if mode == "solid-oidc" && req.ClientID == "" {
		http.Error(w, "client_id is required", http.StatusBadRequest)
		return
	}
	if req.AuthorizationServer == "" {
		http.Error(w, "authorization_server is required", http.StatusBadRequest)
		return
	}

	// Step 2: Fetch OIDC configuration
	oidcConfig, err := fetchOIDCConfig(issuer)
	if err != nil {
		logrus.WithError(err).Error("Unable to fetch OIDC configuration")
		http.Error(w, "Unable to fetch OIDC configuration", http.StatusInternalServerError)
		return
	}

	// Step 3: Generate PKCE challenge and verifier
	codeVerifier, codeChallenge, err := generatePKCE()
	if err != nil {
		logrus.WithError(err).Error("Failed to generate PKCE")
		http.Error(w, "Failed to generate PKCE", http.StatusInternalServerError)
		return
	}

	// Step 4: Generate state
	state, err := generateRandomState()
	if err != nil {
		logrus.WithError(err).Error("Failed to generate state")
		http.Error(w, "Failed to generate state", http.StatusInternalServerError)
		return
	}

	// Step 5: Store state with PKCE verifier and request details
	stateStoreMu.Lock()
	stateStore[state] = storedState{
		OwnerID:             id,
		AuthorizationServer: req.AuthorizationServer,
		AggregatorID:        req.AggregatorID,
		ClientID:            req.ClientID,
		CodeVerifier:        codeVerifier,
		IDPIssuer:           issuer,
		TokenEndpoint:       oidcConfig.TokenEndpoint,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}
	stateStoreMu.Unlock()

	logrus.Infof("Authorization code flow started for ID %s (state=%s)", id, state)

	var clientId string
	if mode == "solid-oidc" {
		clientId = model.SolidClientId
	} else {
		clientId = model.OIDCClientId
	}

	// Step 6: Return public parameters to client
	response := model.AuthorizationCodeStartResponse{
		AggregatorClientID:  clientId,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: "S256",
		State:               state,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logrus.WithError(err).Error("Failed to write response")
	}
}

// handleAuthorizationCodeFinish handles the finish phase of authorization_code flow
func handleAuthorizationCodeFinish(w http.ResponseWriter, req model.RegistrationRequest, id string, mode string) {
	// Validate required fields
	if req.Code == "" {
		http.Error(w, "code is required", http.StatusBadRequest)
		return
	}
	if req.RedirectURI == "" {
		http.Error(w, "redirect_uri is required", http.StatusBadRequest)
		return
	}
	if req.State == "" {
		http.Error(w, "state is required", http.StatusBadRequest)
		return
	}

	// Retrieve and validate state
	stateStoreMu.Lock()
	storedData, ok := stateStore[req.State]
	if ok {
		delete(stateStore, req.State)
	}
	stateStoreMu.Unlock()

	if !ok {
		logrus.Warnf("Invalid or expired state: %s", req.State)
		http.Error(w, "Invalid or expired state", http.StatusBadRequest)
		return
	}

	if time.Now().After(storedData.ExpiresAt) {
		http.Error(w, "State expired", http.StatusBadRequest)
		return
	}

	// Verify the request is from the same user
	if storedData.OwnerID != id {
		logrus.Warnf("ID mismatch: stored=%s, request=%s", storedData.OwnerID, id)
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	if mode == "solid-oidc" {
		if err := validateRedirectURI(req.RedirectURI, storedData.ClientID); err != nil {
			logrus.WithError(err).Warn("Redirect URI validation failed")
			http.Error(w, "redirect_uri not allowed", http.StatusBadRequest)
			return
		}
	}

	// Exchange authorization code for tokens
	var data url.Values
	if mode == "solid-oidc" {
		data = url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {req.Code},
			"redirect_uri":  {req.RedirectURI},
			"client_id":     {model.SolidClientId},
			"code_verifier": {storedData.CodeVerifier},
		}
	} else {
		data = url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {req.Code},
			"redirect_uri":  {req.RedirectURI},
			"client_id":     {model.OIDCClientId},
			"client_secret": {model.OIDCClientSecret},
			"code_verifier": {storedData.CodeVerifier},
		}
	}

	resp, err := model.HttpClient.PostForm(storedData.TokenEndpoint, data)
	if err != nil {
		logrus.WithError(err).Error("Token exchange failed")
		http.Error(w, "Token exchange failed", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		logrus.Errorf("Token endpoint returned %d: %s", resp.StatusCode, string(body))
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

	// Determine if this is create or update
	isUpdate := storedData.AggregatorID != ""

	var inst *instance.AggregatorInstance
	if isUpdate {
		// Check if aggregator exists
		inst, err := instance.GetAggregatorInstance(storedData.AggregatorID)
		if err != nil {
			logrus.WithError(err).Error("Failed to retrieve aggregator for update")
			http.Error(w, "Aggregator not found for update", http.StatusNotFound)
			return
		}

		// Is user authorized to update this aggregator?
		if !inst.HasOwnership(id) {
			logrus.Warnf("User %s not authorized to update aggregator %s", id, storedData.AggregatorID)
			http.Error(w, "Not authorized to update this aggregator", http.StatusForbidden)
			return
		}

		if mode == "solid-oidc" {
			err = updateTokens(id, tokenResp, storedData.IDPIssuer, model.SolidClientId, "")
		} else {
			err = updateTokens(id, tokenResp, model.OIDCServer, model.OIDCClientId, model.OIDCClientSecret)
		}
		if err != nil {
			logrus.WithError(err).Error("Failed to update user tokens")
			http.Error(w, "Failed to update user tokens", http.StatusInternalServerError)
			return
		}
		logrus.Infof("Aggregator tokens updated: %s", storedData.AggregatorID)
	} else {
		// Store user tokens
		if mode == "solid-oidc" {
			err = storeTokens(id, tokenResp, storedData.IDPIssuer, model.SolidClientId, "")
		} else {
			err = storeTokens(id, tokenResp, model.OIDCServer, model.OIDCClientId, model.OIDCClientSecret)
		}
		if err != nil {
			logrus.WithError(err).Error("Failed to store user tokens")
			http.Error(w, "Failed to store user tokens", http.StatusInternalServerError)
			return
		}

		// Create new aggregator instance
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Deploy aggregator instance
		aggregatorId, err := instance.DeployAggregator(
			id,
			storedData.AuthorizationServer,
			"",
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
			"authorization_code",
			storedData.AuthorizationServer,
			aggregatorId,
		)

		logrus.Infof("Aggregator created: %s for ID %s", inst.AggregatorID, id)
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

func validateRedirectURI(redirectURI string, clientID string) error {
	if clientID == "" {
		return nil
	}

	redirectURIs, err := fetchClientRedirectURIs(clientID)
	if err != nil {
		return err
	}

	if len(redirectURIs) == 0 {
		return nil
	}

	for _, allowed := range redirectURIs {
		if redirectURI == allowed {
			return nil
		}
	}

	return fmt.Errorf("redirect_uri not registered")
}

func fetchClientRedirectURIs(clientID string) ([]string, error) {
	parsed, err := url.Parse(clientID)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		logrus.Warnf("Client ID is not a URL, skipping redirect_uri validation: %s", clientID)
		return nil, nil
	}

	req, err := http.NewRequest(http.MethodGet, clientID, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("client metadata document returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var doc struct {
		RedirectURIs []string `json:"redirect_uris"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}

	return doc.RedirectURIs, nil
}
