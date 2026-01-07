package mocks

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"time"
)

// OIDCProvider mocks an OpenID Connect Identity Provider
type OIDCProvider struct {
	server        *httptest.Server
	privateKey    *rsa.PrivateKey
	publicKey     *rsa.PublicKey
	issuer        string
	mu            sync.RWMutex
	users         map[string]*User
	clients       map[string]*Client
	authCodes     map[string]*AuthorizationCode
	tokens        map[string]*TokenInfo
	refreshTokens map[string]*RefreshTokenInfo
	clientMetadataRedirectURIs []string
}

type User struct {
	WebID    string
	Username string
	Password string
}

type Client struct {
	ClientID     string
	ClientSecret string
	RedirectURIs []string
	GrantTypes   []string
}

type AuthorizationCode struct {
	Code                string
	ClientID            string
	RedirectURI         string
	WebID               string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
}

type TokenInfo struct {
	AccessToken string
	WebID       string
	ClientID    string
	Scopes      []string
	ExpiresAt   time.Time
}

type RefreshTokenInfo struct {
	RefreshToken string
	WebID        string
	ClientID     string
	Scopes       []string
}

// NewOIDCProvider creates a new mock OIDC provider
func NewOIDCProvider() (*OIDCProvider, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	provider := &OIDCProvider{
		privateKey:    privateKey,
		publicKey:     &privateKey.PublicKey,
		users:         make(map[string]*User),
		clients:       make(map[string]*Client),
		authCodes:     make(map[string]*AuthorizationCode),
		tokens:        make(map[string]*TokenInfo),
		refreshTokens: make(map[string]*RefreshTokenInfo),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", provider.handleDiscovery)
	mux.HandleFunc("/.well-known/jwks.json", provider.handleJWKS)
	mux.HandleFunc("/authorize", provider.handleAuthorize)
	mux.HandleFunc("/token", provider.handleToken)
	mux.HandleFunc("/userinfo", provider.handleUserInfo)
	mux.HandleFunc("/introspect", provider.handleIntrospect)
	mux.HandleFunc("/register", provider.handleDynamicRegistration)
	mux.HandleFunc("/webid", provider.handleWebID) // Serve WebID documents
	mux.HandleFunc("/client-metadata", provider.handleClientMetadata)

	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return nil, fmt.Errorf("failed to listen for mock OIDC provider: %w", err)
	}

	server := httptest.NewUnstartedServer(mux)
	server.Listener = listener
	server.Start()
	provider.server = server

	issuerHost := strings.TrimSpace(os.Getenv("MOCK_OIDC_HOST"))
	if issuerHost == "" {
		issuerHost = "oidc.local"
	}

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		provider.Close()
		return nil, fmt.Errorf("failed to parse mock OIDC listen address: %w", err)
	}

	issuer, err := buildIssuerURL(issuerHost, port)
	if err != nil {
		provider.Close()
		return nil, err
	}
	provider.issuer = issuer

	return provider, nil
}

// Close shuts down the mock server
func (p *OIDCProvider) Close() {
	p.server.Close()
}

// URL returns the base URL of the mock OIDC provider
func (p *OIDCProvider) URL() string {
	return p.issuer
}

func (p *OIDCProvider) ClientMetadataURL(redirectURIs []string) string {
	p.mu.Lock()
	p.clientMetadataRedirectURIs = append([]string(nil), redirectURIs...)
	p.mu.Unlock()

	return p.issuer + "/client-metadata"
}

type clientIdentifierDocument struct {
	ClientID string `json:"client_id"`
}

func resolveClientID(clientID string) (string, error) {
	if strings.HasPrefix(clientID, "http://") || strings.HasPrefix(clientID, "https://") {
		req, err := http.NewRequest("GET", clientID, nil)
		if err != nil {
			return "", fmt.Errorf("invalid client_id URL")
		}
		req.Header.Set("Accept", "application/ld+json, application/json")

		client := &http.Client{
			Timeout: 5 * time.Second,
		}
		resp, err := client.Do(req)
		if err != nil {
			return "", fmt.Errorf("failed to dereference client_id")
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("client_id dereference returned %d", resp.StatusCode)
		}

		var doc clientIdentifierDocument
		if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
			return "", fmt.Errorf("invalid client_id document")
		}

		if doc.ClientID == "" {
			return "", fmt.Errorf("client_id missing from document")
		}

		return doc.ClientID, nil
	}

	if clientID == "" {
		return "", fmt.Errorf("client_id required")
	}

	return clientID, nil
}

func buildIssuerURL(host, port string) (string, error) {
	if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
		return host, nil
	}
	if host == "" {
		return "", fmt.Errorf("empty mock OIDC host")
	}
	if hasExplicitPort(host) {
		return "http://" + normalizeHost(host), nil
	}
	return fmt.Sprintf("http://%s:%s", normalizeHost(host), port), nil
}

func hasExplicitPort(host string) bool {
	if strings.HasPrefix(host, "[") {
		_, _, err := net.SplitHostPort(host)
		return err == nil
	}
	return strings.Count(host, ":") == 1
}

func normalizeHost(host string) string {
	if strings.HasPrefix(host, "[") {
		return host
	}
	if strings.Count(host, ":") >= 2 {
		return "[" + host + "]"
	}
	return host
}

// RegisterUser adds a user to the mock provider
func (p *OIDCProvider) RegisterUser(webID, username, password string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.users[username] = &User{
		WebID:    webID,
		Username: username,
		Password: password,
	}
}

// RegisterClient adds a client to the mock provider
func (p *OIDCProvider) RegisterClient(clientID, clientSecret string, redirectURIs []string, grantTypes []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clients[clientID] = &Client{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURIs: redirectURIs,
		GrantTypes:   grantTypes,
	}
}

// InvalidateToken marks a token as invalid
func (p *OIDCProvider) InvalidateToken(accessToken string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.tokens, accessToken)
}

// InvalidateRefreshToken marks a refresh token as invalid
func (p *OIDCProvider) InvalidateRefreshToken(refreshToken string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.refreshTokens, refreshToken)
}

// IssueTokenForWebID creates a valid JWT token for a given WebID (for testing)
func (p *OIDCProvider) IssueTokenForWebID(webID string) (string, error) {
	scopes := []string{"openid", "webid"}
	token, err := p.generateIDToken(webID, "test-client", "")
	if err != nil {
		return "", err
	}

	// Store the token as valid
	p.mu.Lock()
	p.tokens[token] = &TokenInfo{
		AccessToken: token,
		WebID:       webID,
		ClientID:    "test-client",
		Scopes:      scopes,
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}
	p.mu.Unlock()

	return token, nil
}

func (p *OIDCProvider) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	discovery := map[string]interface{}{
		"issuer":                                p.issuer,
		"authorization_endpoint":                p.issuer + "/authorize",
		"token_endpoint":                        p.issuer + "/token",
		"userinfo_endpoint":                     p.issuer + "/userinfo",
		"jwks_uri":                              p.issuer + "/.well-known/jwks.json",
		"registration_endpoint":                 p.issuer + "/register",
		"introspection_endpoint":                p.issuer + "/introspect",
		"response_types_supported":              []string{"code", "token", "id_token"},
		"grant_types_supported":                 []string{"authorization_code", "client_credentials", "refresh_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "webid", "offline_access"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"code_challenge_methods_supported":      []string{"S256"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(discovery)
}

func (p *OIDCProvider) handleJWKS(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement JWKS endpoint
	// Return public key in JWK format for token verification
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"keys": []interface{}{},
	})
}

func (p *OIDCProvider) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	responseType := query.Get("response_type")
	clientID := query.Get("client_id")
	redirectURI := query.Get("redirect_uri")
	state := query.Get("state")
	codeChallenge := query.Get("code_challenge")
	codeChallengeMethod := query.Get("code_challenge_method")
	scope := query.Get("scope")

	if responseType != "code" {
		http.Error(w, "Unsupported response_type", http.StatusBadRequest)
		return
	}

	clientID, err := resolveClientID(clientID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	p.mu.RLock()
	client, exists := p.clients[clientID]
	p.mu.RUnlock()

	if !exists {
		http.Error(w, "Unknown client_id", http.StatusBadRequest)
		return
	}

	validRedirect := false
	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			validRedirect = true
			break
		}
	}
	if !validRedirect {
		http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
		return
	}

	code := generateRandomString(32)

	p.mu.Lock()
	p.authCodes[code] = &AuthorizationCode{
		Code:                code,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		WebID:               "https://user.example/webid#me",
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}
	p.mu.Unlock()

	redirectURL := fmt.Sprintf("%s?code=%s&state=%s", redirectURI, code, state)
	if scope != "" {
		redirectURL += "&scope=" + scope
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (p *OIDCProvider) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")

	switch grantType {
	case "authorization_code":
		p.handleAuthorizationCodeGrant(w, r)
	case "client_credentials":
		p.handleClientCredentialsGrant(w, r)
	case "refresh_token":
		p.handleRefreshTokenGrant(w, r)
	default:
		http.Error(w, "Unsupported grant type", http.StatusBadRequest)
	}
}

func (p *OIDCProvider) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")
	clientID := r.FormValue("client_id")

	clientID, clientSecret, ok := extractClientCredentials(r, clientID)
	if !ok {
		http.Error(w, "Invalid client authentication", http.StatusUnauthorized)
		return
	}

	clientID, err := resolveClientID(clientID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	p.mu.Lock()
	authCode, exists := p.authCodes[code]
	if exists {
		delete(p.authCodes, code)
	}
	p.mu.Unlock()

	if !exists {
		http.Error(w, "Invalid authorization code", http.StatusBadRequest)
		return
	}

	if time.Now().After(authCode.ExpiresAt) {
		http.Error(w, "Authorization code expired", http.StatusBadRequest)
		return
	}

	if authCode.ClientID != clientID {
		http.Error(w, "Client mismatch", http.StatusBadRequest)
		return
	}

	if authCode.RedirectURI != redirectURI {
		http.Error(w, "Redirect URI mismatch", http.StatusBadRequest)
		return
	}

	p.mu.RLock()
	client, exists := p.clients[clientID]
	p.mu.RUnlock()

	if !exists || client.ClientSecret != clientSecret {
		http.Error(w, "Invalid client credentials", http.StatusUnauthorized)
		return
	}

	if authCode.CodeChallenge != "" {
		if codeVerifier == "" {
			http.Error(w, "Code verifier required", http.StatusBadRequest)
			return
		}
		if !verifyPKCE(codeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod) {
			http.Error(w, "Invalid code verifier", http.StatusBadRequest)
			return
		}
	}

	scopes := []string{"openid", "webid", "offline_access"}
	accessToken := generateRandomString(32)
	refreshToken := generateRandomString(32)

	p.mu.Lock()
	p.tokens[accessToken] = &TokenInfo{
		AccessToken: accessToken,
		WebID:       authCode.WebID,
		ClientID:    clientID,
		Scopes:      scopes,
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}
	p.refreshTokens[refreshToken] = &RefreshTokenInfo{
		RefreshToken: refreshToken,
		WebID:        authCode.WebID,
		ClientID:     clientID,
		Scopes:       scopes,
	}
	p.mu.Unlock()

	idToken, err := p.generateIDToken(authCode.WebID, clientID, "")
	if err != nil {
		http.Error(w, "Failed to generate ID token", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": refreshToken,
		"id_token":      idToken,
		"scope":         strings.Join(scopes, " "),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (p *OIDCProvider) handleClientCredentialsGrant(w http.ResponseWriter, r *http.Request) {
	clientID := r.FormValue("client_id")
	webID := r.FormValue("webid")
	scope := r.FormValue("scope")

	clientID, clientSecret, ok := extractClientCredentials(r, clientID)
	if !ok {
		http.Error(w, "Invalid client authentication", http.StatusUnauthorized)
		return
	}

	clientID, err := resolveClientID(clientID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	p.mu.RLock()
	client, exists := p.clients[clientID]
	p.mu.RUnlock()

	if !exists || client.ClientSecret != clientSecret {
		http.Error(w, "Invalid client credentials", http.StatusUnauthorized)
		return
	}

	hasGrantType := false
	for _, gt := range client.GrantTypes {
		if gt == "client_credentials" {
			hasGrantType = true
			break
		}
	}
	if !hasGrantType {
		http.Error(w, "Grant type not allowed for this client", http.StatusBadRequest)
		return
	}

	if webID == "" {
		webID = "https://aggregator.example/webid#me"
	}

	scopes := []string{"openid", "webid"}
	if scope != "" {
		scopes = strings.Split(scope, " ")
	}

	accessToken := generateRandomString(32)
	refreshToken := generateRandomString(32)

	p.mu.Lock()
	p.tokens[accessToken] = &TokenInfo{
		AccessToken: accessToken,
		WebID:       webID,
		ClientID:    clientID,
		Scopes:      scopes,
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}
	p.refreshTokens[refreshToken] = &RefreshTokenInfo{
		RefreshToken: refreshToken,
		WebID:        webID,
		ClientID:     clientID,
		Scopes:       scopes,
	}
	p.mu.Unlock()

	response := map[string]interface{}{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": refreshToken,
		"scope":         strings.Join(scopes, " "),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (p *OIDCProvider) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	refreshToken := r.FormValue("refresh_token")
	clientID := r.FormValue("client_id")

	clientID, clientSecret, ok := extractClientCredentials(r, clientID)
	if !ok {
		http.Error(w, "Invalid client authentication", http.StatusUnauthorized)
		return
	}

	clientID, err := resolveClientID(clientID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	p.mu.RLock()
	client, exists := p.clients[clientID]
	rtInfo, rtExists := p.refreshTokens[refreshToken]
	p.mu.RUnlock()

	if !exists || client.ClientSecret != clientSecret {
		http.Error(w, "Invalid client credentials", http.StatusUnauthorized)
		return
	}

	if !rtExists {
		http.Error(w, "Invalid refresh token", http.StatusBadRequest)
		return
	}

	if rtInfo.ClientID != clientID {
		http.Error(w, "Client mismatch", http.StatusBadRequest)
		return
	}

	accessToken := generateRandomString(32)
	newRefreshToken := generateRandomString(32)

	p.mu.Lock()
	delete(p.refreshTokens, refreshToken)
	p.tokens[accessToken] = &TokenInfo{
		AccessToken: accessToken,
		WebID:       rtInfo.WebID,
		ClientID:    clientID,
		Scopes:      rtInfo.Scopes,
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}
	p.refreshTokens[newRefreshToken] = &RefreshTokenInfo{
		RefreshToken: newRefreshToken,
		WebID:        rtInfo.WebID,
		ClientID:     clientID,
		Scopes:       rtInfo.Scopes,
	}
	p.mu.Unlock()

	response := map[string]interface{}{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": newRefreshToken,
		"scope":         strings.Join(rtInfo.Scopes, " "),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (p *OIDCProvider) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Missing or invalid Authorization header", http.StatusUnauthorized)
		return
	}

	accessToken := strings.TrimPrefix(authHeader, "Bearer ")

	p.mu.RLock()
	tokenInfo, exists := p.tokens[accessToken]
	p.mu.RUnlock()

	if !exists {
		http.Error(w, "Invalid access token", http.StatusUnauthorized)
		return
	}

	if time.Now().After(tokenInfo.ExpiresAt) {
		http.Error(w, "Access token expired", http.StatusUnauthorized)
		return
	}

	userInfo := map[string]interface{}{
		"sub":   tokenInfo.WebID,
		"webid": tokenInfo.WebID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
}

func (p *OIDCProvider) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	token := r.FormValue("token")
	if token == "" {
		http.Error(w, "Missing token parameter", http.StatusBadRequest)
		return
	}

	p.mu.RLock()
	tokenInfo, exists := p.tokens[token]
	p.mu.RUnlock()

	response := map[string]interface{}{
		"active": false,
	}

	if exists && time.Now().Before(tokenInfo.ExpiresAt) {
		response = map[string]interface{}{
			"active":    true,
			"sub":       tokenInfo.WebID,
			"webid":     tokenInfo.WebID,
			"client_id": tokenInfo.ClientID,
			"scope":     strings.Join(tokenInfo.Scopes, " "),
			"exp":       tokenInfo.ExpiresAt.Unix(),
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (p *OIDCProvider) handleDynamicRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var regReq struct {
		RedirectURIs []string `json:"redirect_uris"`
		GrantTypes   []string `json:"grant_types"`
		WebID        string   `json:"webid"`
	}

	if err := json.NewDecoder(r.Body).Decode(&regReq); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if len(regReq.RedirectURIs) == 0 {
		http.Error(w, "redirect_uris required", http.StatusBadRequest)
		return
	}

	if len(regReq.GrantTypes) == 0 {
		regReq.GrantTypes = []string{"authorization_code", "client_credentials"}
	}

	clientID := "https://aggregator.example/client-" + generateRandomString(16)
	clientSecret := generateRandomString(32)

	p.RegisterClient(clientID, clientSecret, regReq.RedirectURIs, regReq.GrantTypes)

	if regReq.WebID != "" {
		p.RegisterUser(regReq.WebID, "provisioned-user", "provisioned-pass")
	}

	response := map[string]interface{}{
		"client_id":     clientID,
		"client_secret": clientSecret,
		"redirect_uris": regReq.RedirectURIs,
		"grant_types":   regReq.GrantTypes,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// handleWebID serves WebID documents in Turtle format
func (p *OIDCProvider) handleWebID(w http.ResponseWriter, r *http.Request) {
	// Serve a WebID document that points back to this OIDC provider
	// This allows the aggregator to discover the IDP from the WebID
	webIDDoc := fmt.Sprintf(`@prefix foaf: <http://xmlns.com/foaf/0.1/> .
@prefix solid: <http://www.w3.org/ns/solid/terms#> .

<#me>
    a foaf:Person ;
    foaf:name "Test User" ;
    solid:oidcIssuer <%s> .
`, p.issuer)

	w.Header().Set("Content-Type", "text/turtle")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(webIDDoc))
}

func (p *OIDCProvider) handleClientMetadata(w http.ResponseWriter, r *http.Request) {
	p.mu.RLock()
	redirectURIs := append([]string(nil), p.clientMetadataRedirectURIs...)
	p.mu.RUnlock()

	response := map[string]interface{}{
		"client_id": p.issuer + "/client-metadata",
	}
	if len(redirectURIs) > 0 {
		response["redirect_uris"] = redirectURIs
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode client metadata", http.StatusInternalServerError)
	}
}

// generateToken creates a JWT access token
func (p *OIDCProvider) generateToken(webID, clientID string, scopes []string, expiresIn time.Duration) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":   p.issuer,
		"sub":   webID,
		"aud":   clientID,
		"exp":   now.Add(expiresIn).Unix(),
		"iat":   now.Unix(),
		"scope": strings.Join(scopes, " "),
		"webid": webID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(p.privateKey)
}

// generateIDToken creates a JWT ID token
func (p *OIDCProvider) generateIDToken(webID, clientID string, nonce string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":   p.issuer,
		"sub":   webID,
		"aud":   clientID,
		"exp":   now.Add(1 * time.Hour).Unix(),
		"iat":   now.Unix(),
		"webid": webID,
	}

	if nonce != "" {
		claims["nonce"] = nonce
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(p.privateKey)
}

// generateRandomString generates a random string for codes and tokens
func generateRandomString(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)[:length]
}

// verifyPKCE verifies the PKCE code verifier against the challenge
func verifyPKCE(verifier, challenge, method string) bool {
	if method != "S256" {
		return false
	}

	h := sha256.New()
	h.Write([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return computed == challenge
}

// extractClientCredentials extracts client credentials from Basic auth or form body
func extractClientCredentials(r *http.Request, formClientID string) (clientID, clientSecret string, ok bool) {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Basic ") {
		encoded := strings.TrimPrefix(authHeader, "Basic ")
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return "", "", false
		}
		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) != 2 {
			return "", "", false
		}
		return parts[0], parts[1], true
	}

	clientSecret = r.FormValue("client_secret")
	if formClientID != "" && clientSecret != "" {
		return formClientID, clientSecret, true
	}

	return "", "", false
}
