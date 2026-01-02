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
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

var (
	users   = make(map[string]*model.User)
	userMux sync.Mutex
)

func RegistrationHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		logrus.Warnf("Registration attempt with wrong method: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req model.RegistrationRequest
	contentType := r.Header.Get("Content-Type")
	logrus.Debugf("Registration request content-type: %s", contentType)

	// Parse JSON
	if contentType == "application/json" || strings.HasPrefix(contentType, "application/json;") {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logrus.WithError(err).Warn("Invalid JSON body")
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
	} else {
		// Parse form
		if err := r.ParseForm(); err != nil {
			logrus.WithError(err).Warn("Invalid form body")
			http.Error(w, "Invalid form body", http.StatusBadRequest)
			return
		}
		req.UserIdp = r.FormValue("openid_provider")
		req.AuthzServerURL = r.FormValue("as_url")
	}

	// Required fields
	if req.UserIdp == "" || req.AuthzServerURL == "" {
		logrus.Warn("Missing required fields (openid_provider or as_url)")
		http.Error(w, "missing required fields", http.StatusBadRequest)
		return
	}

	// Fetch OIDC Config
	oidcConfig, err := fetchOIDCConfig(req.UserIdp)
	if err != nil {
		logrus.WithError(err).Error("Unable to fetch OIDC configuration")
		// Note: not throwing error upward — handler ends here → log it
		http.Error(w, "unable to fetch oidc configuration", http.StatusInternalServerError)
		return
	}
	req.OIDCConfig = *oidcConfig

	// Generate PKCE code challenge and verifier
	codeVerifier, codeChallenge, err := generatePKCE()
	if err != nil {
		logrus.WithError(err).Error("PKCE failed")
		http.Error(w, "Failed to generate PKCE code challenge and verifier", http.StatusInternalServerError)
	}
	req.CodeVerifier = codeVerifier

	// Generate random state
	state, err := generateRandomState()
	if err != nil {
		logrus.WithError(err).Error("Failed to generate state")
		http.Error(w, "Failed to generate state", http.StatusInternalServerError)
		return
	}

	// Store state
	stateStoreMu.Lock()
	stateStore[state] = storedState{
		Req:       req,
		ExpiresAt: time.Now().Add(10 * time.Minute), // recommended TTL
	}
	stateStoreMu.Unlock()
	logrus.Debugf("Stored registration request for state %s", state)

	// Construct response metadata
	callbackURI := fmt.Sprintf("%s://%s/registration/callback", model.Protocol, model.ExternalHost)
	response := map[string]string{
		"callback_uri":          callbackURI,
		"state":                 state,
		"scope":                 "openid profile email offline_access",
		"response_type":         "code",
		"client_id":             model.ClientId,
		"code_challenge_method": "S256",
		"code_challenge":        codeChallenge,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logrus.WithError(err).Error("Failed to write registration response")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	logrus.Infof("Registration initialization successful (state=%s)", state)
}

func RegistrationCallback(w http.ResponseWriter, r *http.Request) {
	logrus.Debug("Entered RegistrationCallback")

	// Method check
	if r.Method != http.MethodPost {
		logrus.Warnf("RegistrationCallback: wrong method %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var reqBody struct {
		Code        string `json:"code"`
		State       string `json:"state"`
		RedirectUri string `json:"redirect_uri"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		logrus.WithError(err).Warn("Invalid JSON body in registration callback")
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if reqBody.Code == "" || reqBody.State == "" {
		logrus.Warn("Missing code or state in registration callback")
		http.Error(w, "Missing code or state", http.StatusBadRequest)
		return
	}

	logrus.Debugf("Received registration callback: code='%s', state='%s'", reqBody.Code, reqBody.State)

	stateStoreMu.Lock()
	entry, ok := stateStore[reqBody.State]
	if ok {
		delete(stateStore, reqBody.State)
	}
	stateStoreMu.Unlock()

	if !ok {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	if time.Now().After(entry.ExpiresAt) {
		http.Error(w, "State expired", http.StatusBadRequest)
		return
	}

	regReq := entry.Req

	// Prepare token request
	tokenEndpoint := regReq.OIDCConfig.TokenEndpoint
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {reqBody.Code},
		"redirect_uri":  {reqBody.RedirectUri},
		"client_id":     {model.ClientId},
		"client_secret": {model.ClientSecret},
		"code_verifier": {regReq.CodeVerifier},
	}

	resp, err := http.PostForm(tokenEndpoint, data)
	if err != nil {
		logrus.WithError(err).Error("Token exchange failed during registration callback")
		http.Error(w, "Token exchange failed", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Token endpoint returned an error response
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		logrus.Errorf("Token endpoint returned %d: %s", resp.StatusCode, string(body))
		http.Error(w, fmt.Sprintf("Token endpoint error: %s", string(body)), http.StatusBadGateway)
		return
	}

	// Parse token response
	var tokenResp struct {
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

	// Verify ID token
	idToken, err := verifyToken(tokenResp.IDToken, regReq.UserIdp)
	if err != nil {
		logrus.WithError(err).Error("Failed to verify ID token")
		http.Error(w, "ID token verification failed", http.StatusUnauthorized)
		return
	}

	// Validate ID token subject
	userId, err := validateToken(idToken, regReq.UserIdp)
	if err != nil {
		logrus.WithError(err).Error("Failed to validate ID token")
		http.Error(w, "ID token validation failed", http.StatusUnauthorized)
		return
	}

	// Create user model
	user := model.User{
		UserId:         userId,
		RefreshToken:   tokenResp.RefreshToken,
		AuthzServerURL: regReq.AuthzServerURL,
	}

	userMux.Lock()
	defer userMux.Unlock()

	if _, exists := users[user.UserId]; exists {
		logrus.Warnf("User already exists: %s", user.UserId)
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	// Create namespace for user
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ns, err := createNamespace(user, ctx)
	if err != nil {
		logrus.WithError(err).Errorf("Failed to create namespace for user: %s", user.UserId)
		http.Error(w, "Failed to create namespace", http.StatusInternalServerError)
		return
	}
	user.Namespace = ns

	// Deploy Aggregator Instance & UMA Proxy
	if err := createAggregatorInstance(1, ns, user, tokenEndpoint, ctx); err != nil {
		logrus.WithError(err).Errorf("Failed to deploy Aggregator Instance for user: %s", user.UserId)
		http.Error(w, "Failed to deploy Aggregator Instance", http.StatusInternalServerError)
		return
	}

	// Add user to store
	users[user.UserId] = &user

	logrus.Infof("User registration completed successfully: %s", user.UserId)

	// Return final endpoints
	endpoints := user.ConfigEndpoints()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(endpoints); err != nil {
		logrus.WithError(err).Error("Failed to write endpoints JSON")
		http.Error(w, "Failed to return endpoints", http.StatusInternalServerError)
		return
	}
}
