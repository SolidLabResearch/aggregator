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

// handleAuthorizationCodeFlow handles the authorization_code registration type
func handleAuthorizationCodeFlow(w http.ResponseWriter, req model.RegistrationRequest, ownerWebID string) {
	// Check if this is start or finish phase
	if req.Code == "" {
		// Start phase
		handleAuthorizationCodeStart(w, req, ownerWebID)
	} else {
		// Finish phase
		handleAuthorizationCodeFinish(w, req, ownerWebID)
	}
}

// handleAuthorizationCodeStart handles the start phase of authorization_code flow
func handleAuthorizationCodeStart(w http.ResponseWriter, req model.RegistrationRequest, ownerWebID string) {
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

	// Step 1: Dereference WebID to discover IDP
	// The WebID should contain a solid:oidcIssuer claim pointing to the IDP
	idpIssuer, err := discoverIDPFromWebID(ownerWebID)
	if err != nil {
		logrus.WithError(err).Errorf("Failed to discover IDP from WebID: %s", ownerWebID)
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
		OwnerWebID:          ownerWebID,
		AuthorizationServer: req.AuthorizationServer,
		AggregatorID:        req.AggregatorID,
		ClientID:            req.ClientID,
		CodeVerifier:        codeVerifier,
		IDPIssuer:           idpIssuer,
		TokenEndpoint:       oidcConfig.TokenEndpoint,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}
	stateStoreMu.Unlock()

	logrus.Infof("Authorization code flow started for WebID %s (state=%s)", ownerWebID, state)

	// Step 6: Return public parameters to client
	response := model.AuthorizationCodeStartResponse{
		AggregatorClientID:  model.ClientId,
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
func handleAuthorizationCodeFinish(w http.ResponseWriter, req model.RegistrationRequest, ownerWebID string) {
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
	if storedData.OwnerWebID != ownerWebID {
		logrus.Warnf("WebID mismatch: stored=%s, request=%s", storedData.OwnerWebID, ownerWebID)
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	if err := validateRedirectURI(req.RedirectURI, storedData.ClientID); err != nil {
		logrus.WithError(err).Warn("Redirect URI validation failed")
		http.Error(w, "redirect_uri not allowed", http.StatusBadRequest)
		return
	}

	// Exchange authorization code for tokens
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {req.Code},
		"redirect_uri":  {req.RedirectURI},
		"client_id":     {model.ClientId},
		"client_secret": {model.ClientSecret},
		"code_verifier": {storedData.CodeVerifier},
	}

	resp, err := http.PostForm(storedData.TokenEndpoint, data)
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
	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		logrus.WithError(err).Error("Failed to parse token response")
		http.Error(w, "Invalid token response", http.StatusInternalServerError)
		return
	}

	// Determine if this is create or update
	isUpdate := storedData.AggregatorID != ""

	var instance *model.AggregatorInstance
	if isUpdate {
		// Update existing aggregator tokens
		if err := updateAggregatorInstanceTokens(storedData.AggregatorID, tokenResp.AccessToken, tokenResp.RefreshToken); err != nil {
			logrus.WithError(err).Errorf("Failed to update aggregator tokens: %s", storedData.AggregatorID)
			http.Error(w, "Failed to update aggregator", http.StatusInternalServerError)
			return
		}
		instance, _ = getAggregatorInstance(storedData.AggregatorID)
		logrus.Infof("Aggregator tokens updated: %s", storedData.AggregatorID)
	} else {
		// Create new aggregator instance
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Create namespace
		namespace, err := createNamespaceForAggregator(ownerWebID, storedData.AuthorizationServer, ctx)
		if err != nil {
			logrus.WithError(err).Error("Failed to create namespace")
			http.Error(w, "Failed to create namespace", http.StatusInternalServerError)
			return
		}

		// Deploy aggregator instance
		if err := deployAggregatorResources(namespace, storedData.TokenEndpoint, tokenResp.RefreshToken, ownerWebID, storedData.AuthorizationServer, ctx); err != nil {
			logrus.WithError(err).Error("Failed to deploy aggregator")
			http.Error(w, "Failed to deploy aggregator", http.StatusInternalServerError)
			return
		}

		// Create aggregator record
		instance = createAggregatorInstanceRecord(
			ownerWebID,
			"authorization_code",
			storedData.AuthorizationServer,
			namespace,
			tokenResp.AccessToken,
			tokenResp.RefreshToken,
		)

		logrus.Infof("Aggregator created: %s for WebID %s", instance.AggregatorID, ownerWebID)
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
