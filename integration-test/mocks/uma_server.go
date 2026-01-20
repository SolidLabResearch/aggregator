package mocks

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// UMAAuthorizationServer mocks a UMA 2.0 Authorization Server
type UMAAuthorizationServer struct {
	server            *httptest.Server
	issuer            string
	mu                sync.RWMutex
	resources         map[string]*UMAResource
	tickets           map[string]*UMATicket
	rpts              map[string]*RPT
	policies          map[string]*Policy
	clients           map[string]*RegistrationResponse
	pats              map[string]*PAT
	derivationHandles map[string]*DerivationHandle
	privateKey        *rsa.PrivateKey
	publicKey         *rsa.PublicKey
	jwksKid           string
}

type UMAResource struct {
	ResourceID        string
	Name              string
	Type              string
	Scopes            []string
	Owner             string
	ResourceRelations map[string][]DerivationRef
}

type DerivationRef struct {
	Issuer               string
	DerivationResourceID string
}

type UMATicket struct {
	Ticket     string
	ResourceID string
	Scopes     []string
	ExpiresAt  time.Time
}

type PAT struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

type RPT struct {
	Token       string
	Permissions []Permission
	ExpiresAt   time.Time
}

type Permission struct {
	ResourceID string
	Scopes     []string
}

type Policy struct {
	ResourceID string
	Rules      []PolicyRule
}

type PolicyRule struct {
	Effect   string   // "allow" or "deny"
	Subjects []string // WebIDs
	Scopes   []string
}

type DerivationHandle struct {
	DerivationResourceID string
	ResourceID           string
	Issuer               string
	OwnerWebID           string
	Valid                bool
	CreatedAt            time.Time
}

type RegistrationRequest struct {
	ClientName string `json:"client_name,omitempty"`
	ClientURI  string `json:"client_uri,omitempty"`
}

type RegistrationResponse struct {
	ClientURI               string   `json:"client_uri"`
	ClientName              string   `json:"client_name,omitempty"`
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at"`
	GrantTypes              []string `json:"grant_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

// NewUMAAuthorizationServer creates a new mock UMA AS
func NewUMAAuthorizationServer() *UMAAuthorizationServer {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Errorf("failed to generate UMA RSA key: %w", err))
	}

	as := &UMAAuthorizationServer{
		resources:         make(map[string]*UMAResource),
		tickets:           make(map[string]*UMATicket),
		rpts:              make(map[string]*RPT),
		policies:          make(map[string]*Policy),
		derivationHandles: make(map[string]*DerivationHandle),
		clients:           make(map[string]*RegistrationResponse),
		pats:              make(map[string]*PAT),
		privateKey:        privateKey,
		publicKey:         &privateKey.PublicKey,
		jwksKid:           generateRandomString(8),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/uma2-configuration", as.handleUMAConfiguration)
	mux.HandleFunc("/jwks", as.handleJWKS)
	mux.HandleFunc("/resource_set", as.handleResourceRegistration)
	mux.HandleFunc("/resource_set/", as.handleResourceRegistration)
	mux.HandleFunc("/permission", as.handlePermissionRequest)
	mux.HandleFunc("/token", as.handleTokenRequest)
	mux.HandleFunc("/introspect", as.handleRPTIntrospection)
	mux.HandleFunc("/policy", as.handlePolicyManagement)
	mux.HandleFunc("/policies", as.handlePolicyManagement)
	mux.HandleFunc("/policies/", as.handlePolicyManagement)
	mux.HandleFunc("/register", as.handleRegistration)

	listener, err := net.Listen("tcp", "0.0.0.0:3000")
	if err != nil {
		panic(fmt.Errorf("failed to listen for mock UMA server: %w", err))
	}

	server := httptest.NewUnstartedServer(mux)
	server.Listener = listener
	server.Start()
	as.server = server

	//issuerHost := strings.TrimSpace(os.Getenv("MOCK_UMA_HOST"))
	//if issuerHost == "" {
	//	issuerHost = strings.TrimSpace(os.Getenv("MOCK_OIDC_HOST"))
	//}
	//if issuerHost == "" {
	//	issuerHost = "localhost"
	//}
	issuerHost := "test.local"

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		panic(fmt.Errorf("failed to parse UMA listen address: %w", err))
	}

	issuer, err := buildIssuerURL(issuerHost, port)
	if err != nil {
		panic(err)
	}
	as.issuer = issuer

	return as
}

// Close shuts down the mock server
func (as *UMAAuthorizationServer) Close() {
	as.server.Close()
}

// URL returns the base URL of the mock UMA AS
func (as *UMAAuthorizationServer) URL() string {
	return as.issuer
}

// RegisterResource adds a resource to the UMA AS
func (as *UMAAuthorizationServer) RegisterResource(resourceID, name, owner string, scopes []string) {
	as.mu.Lock()
	defer as.mu.Unlock()
	as.resources[resourceID] = &UMAResource{
		ResourceID:        resourceID,
		Name:              name,
		Scopes:            scopes,
		Owner:             owner,
		ResourceRelations: make(map[string][]DerivationRef),
	}
}

// UpdateResourceRelations updates the prov:wasDerivedFrom relations for a resource
func (as *UMAAuthorizationServer) UpdateResourceRelations(resourceID string, relations map[string][]DerivationRef) error {
	as.mu.Lock()
	defer as.mu.Unlock()

	resource, exists := as.resources[resourceID]
	if !exists {
		return fmt.Errorf("resource not found: %s", resourceID)
	}

	resource.ResourceRelations = relations
	return nil
}

// SetPolicy sets an access policy for a resource
func (as *UMAAuthorizationServer) SetPolicy(resourceID string, rules []PolicyRule) {
	as.mu.Lock()
	defer as.mu.Unlock()
	as.policies[resourceID] = &Policy{
		ResourceID: resourceID,
		Rules:      rules,
	}
}

// CreateDerivationHandle creates a derivation handle for tracking derived resources
func (as *UMAAuthorizationServer) CreateDerivationHandle(resourceID, ownerWebID string) string {
	as.mu.Lock()
	defer as.mu.Unlock()

	derivationID := generateRandomString(32)
	as.derivationHandles[derivationID] = &DerivationHandle{
		DerivationResourceID: derivationID,
		ResourceID:           resourceID,
		Issuer:               as.issuer,
		OwnerWebID:           ownerWebID,
		Valid:                true,
		CreatedAt:            time.Now(),
	}

	return derivationID
}

// InvalidateDerivationHandle marks a derivation handle as invalid
func (as *UMAAuthorizationServer) InvalidateDerivationHandle(derivationResourceID string) {
	as.mu.Lock()
	defer as.mu.Unlock()

	if handle, exists := as.derivationHandles[derivationResourceID]; exists {
		handle.Valid = false
	}
}

// IsDerivationHandleValid checks if a derivation handle is valid
func (as *UMAAuthorizationServer) IsDerivationHandleValid(derivationResourceID string) bool {
	as.mu.RLock()
	defer as.mu.RUnlock()

	handle, exists := as.derivationHandles[derivationResourceID]
	return exists && handle.Valid
}

func (as *UMAAuthorizationServer) handleUMAConfiguration(w http.ResponseWriter, r *http.Request) {
	config := map[string]interface{}{
		"issuer":                                as.issuer,
		"token_endpoint":                        as.issuer + "/token",
		"resource_registration_endpoint":        as.issuer + "/resource_set",
		"permission_endpoint":                   as.issuer + "/permission",
		"introspection_endpoint":                as.issuer + "/introspect",
		"policy_endpoint":                       as.issuer + "/policy",
		"registration_endpoint":                 as.issuer + "/register",
		"jwks_uri":                              as.issuer + "/jwks",
		"grant_types_supported":                 []string{"urn:ietf:params:oauth:grant-type:uma-ticket"},
		"uma_profiles_supported":                []string{"uma_2_0"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

func (as *UMAAuthorizationServer) handleResourceRegistration(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		as.handleResourceListOrDetail(w, r)
	case http.MethodPost:
		as.handleResourceCreate(w, r)
	case http.MethodPut:
		as.handleResourceUpdate(w, r)
	case http.MethodDelete:
		as.handleResourceDelete(w, r)
	default:
		http.Error(w, "Not implemented", http.StatusNotImplemented)
	}
}

func (as *UMAAuthorizationServer) handlePermissionRequest(w http.ResponseWriter, r *http.Request) {
	var permissions []struct {
		ResourceID     string   `json:"resource_id"`
		ResourceScopes []string `json:"resource_scopes"`
	}

	if err := json.NewDecoder(r.Body).Decode(&permissions); err != nil || len(permissions) == 0 {
		http.Error(w, "Invalid permission request", http.StatusBadRequest)
		return
	}

	permission := permissions[0]
	if strings.TrimSpace(permission.ResourceID) == "" || len(permission.ResourceScopes) == 0 {
		http.Error(w, "Missing resource_id or resource_scopes", http.StatusBadRequest)
		return
	}

	ticket := generateRandomString(32)

	as.mu.Lock()
	as.tickets[ticket] = &UMATicket{
		Ticket:     ticket,
		ResourceID: permission.ResourceID,
		Scopes:     permission.ResourceScopes,
		ExpiresAt:  time.Now().Add(5 * time.Minute),
	}
	as.mu.Unlock()

	response := map[string]interface{}{
		"ticket": ticket,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

func (as *UMAAuthorizationServer) handleTokenRequest(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")

	switch grantType {
	case "client_credentials":
		as.handlePATRequest(w, r)
	case "urn:ietf:params:oauth:grant-type:uma-ticket":
		as.handleUMATicketGrant(w, r)
	default:
		http.Error(w, "Unsupported grant type", http.StatusBadRequest)
	}
}

func (as *UMAAuthorizationServer) handleUMATicketGrant(w http.ResponseWriter, r *http.Request) {
	ticket := r.FormValue("ticket")
	if ticket == "" {
		http.Error(w, "ticket is required", http.StatusBadRequest)
		return
	}

	as.mu.Lock()
	umaTicket, exists := as.tickets[ticket]
	if exists {
		delete(as.tickets, ticket)
	}
	as.mu.Unlock()

	if !exists || time.Now().After(umaTicket.ExpiresAt) {
		http.Error(w, "Invalid or expired ticket", http.StatusBadRequest)
		return
	}

	permissions := []Permission{
		{
			ResourceID: umaTicket.ResourceID,
			Scopes:     umaTicket.Scopes,
		},
	}

	token, err := as.issueRPT(permissions)
	if err != nil {
		http.Error(w, "Failed to issue RPT", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   3600,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (as *UMAAuthorizationServer) handlePATRequest(w http.ResponseWriter, r *http.Request) {
	// Check scope
	scope := r.FormValue("scope")
	if scope != "uma_protection" {
		http.Error(w, "Invalid scope", http.StatusBadRequest)
		return
	}

	// Parse Basic Auth
	auth := r.Header.Get("Authorization")
	if auth == "" || !strings.HasPrefix(auth, "Basic ") {
		http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
		return
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil {
		http.Error(w, "Invalid Authorization header", http.StatusUnauthorized)
		return
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		http.Error(w, "Invalid credentials format", http.StatusUnauthorized)
		return
	}

	clientID := parts[0]
	clientSecret := parts[1]

	// (Mock) accept any credentials, or validate if you store them
	_ = clientID
	_ = clientSecret

	// Reuse PAT if still valid
	as.mu.Lock()
	defer as.mu.Unlock()

	if as.pats == nil {
		as.pats = make(map[string]*PAT)
	}

	if token, ok := as.pats[clientID]; ok {
		writeJSON(w, token)
		return
	}

	// Generate new PAT
	token := &PAT{
		AccessToken:  "pat-" + uuid.NewString(),
		RefreshToken: uuid.NewString(),
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		Scope:        "uma_protection",
	}

	as.pats[clientID] = token

	writeJSON(w, token)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (as *UMAAuthorizationServer) handleRPTIntrospection(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement RPT introspection endpoint
	// 1. Extract RPT token from request
	// 2. Authenticate calling client/RS
	// 3. Check if RPT is valid and not expired
	// 4. Return introspection response with permissions
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func (as *UMAAuthorizationServer) handlePolicyManagement(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusCreated)
}

func (as *UMAAuthorizationServer) handleRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	// Generate mock credentials
	clientID := uuid.NewString()
	clientSecret := uuid.NewString() + uuid.NewString()

	resp := RegistrationResponse{
		ClientURI:               req.ClientURI,
		ClientName:              req.ClientName,
		ClientID:                clientID,
		ClientSecret:            clientSecret,
		ClientSecretExpiresAt:   0, // never expires
		GrantTypes:              []string{"client_credentials", "refresh_token"},
		TokenEndpointAuthMethod: "client_secret_basic",
	}

	as.mu.Lock()
	as.clients[clientID] = &resp
	as.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

func (as *UMAAuthorizationServer) handleJWKS(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"keys": []map[string]string{
			{
				"kty": "RSA",
				"kid": as.jwksKid,
				"use": "sig",
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(as.publicKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(as.publicKey.E)).Bytes()),
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (as *UMAAuthorizationServer) handleResourceCreate(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Name           string   `json:"name"`
		ResourceScopes []string `json:"resource_scopes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid resource payload", http.StatusBadRequest)
		return
	}

	resourceID := generateRandomString(12)
	resourceName := payload.Name
	if resourceName == "" {
		resourceName = resourceID
	}

	as.mu.Lock()
	as.resources[resourceID] = &UMAResource{
		ResourceID:        resourceID,
		Name:              resourceName,
		Scopes:            append([]string(nil), payload.ResourceScopes...),
		Owner:             "",
		ResourceRelations: make(map[string][]DerivationRef),
	}
	as.mu.Unlock()

	response := map[string]interface{}{
		"_id": resourceID,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

func (as *UMAAuthorizationServer) handleResourceUpdate(w http.ResponseWriter, r *http.Request) {
	resourceID := extractResourceID(r.URL.Path)
	if resourceID == "" {
		http.Error(w, "Missing resource id", http.StatusBadRequest)
		return
	}

	var payload struct {
		Name           string   `json:"name"`
		ResourceScopes []string `json:"resource_scopes"`
	}
	_ = json.NewDecoder(r.Body).Decode(&payload)

	as.mu.Lock()
	resource, exists := as.resources[resourceID]
	if !exists {
		resource = &UMAResource{
			ResourceID:        resourceID,
			Name:              payload.Name,
			ResourceRelations: make(map[string][]DerivationRef),
		}
		as.resources[resourceID] = resource
	}
	if payload.Name != "" {
		resource.Name = payload.Name
	}
	if len(payload.ResourceScopes) > 0 {
		resource.Scopes = append([]string(nil), payload.ResourceScopes...)
	}
	as.mu.Unlock()

	response := map[string]interface{}{
		"_id": resourceID,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func (as *UMAAuthorizationServer) handleResourceListOrDetail(w http.ResponseWriter, r *http.Request) {
	resourceID := extractResourceID(r.URL.Path)
	if resourceID == "" {
		as.mu.RLock()
		ids := make([]string, 0, len(as.resources))
		for id := range as.resources {
			ids = append(ids, id)
		}
		as.mu.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ids)
		return
	}

	as.mu.RLock()
	resource, exists := as.resources[resourceID]
	as.mu.RUnlock()
	if !exists {
		http.Error(w, "Resource not found", http.StatusNotFound)
		return
	}

	response := map[string]interface{}{
		"_id":             resource.ResourceID,
		"name":            resource.Name,
		"resource_scopes": append([]string(nil), resource.Scopes...),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (as *UMAAuthorizationServer) handleResourceDelete(w http.ResponseWriter, r *http.Request) {
	resourceID := extractResourceID(r.URL.Path)
	if resourceID == "" {
		http.Error(w, "Missing resource id", http.StatusBadRequest)
		return
	}

	as.mu.Lock()
	delete(as.resources, resourceID)
	as.mu.Unlock()

	w.WriteHeader(http.StatusNoContent)
}

func extractResourceID(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-1]
}

func (as *UMAAuthorizationServer) issueRPT(permissions []Permission) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":         as.issuer,
		"aud":         "solid",
		"iat":         now.Unix(),
		"exp":         now.Add(1 * time.Hour).Unix(),
		"permissions": toRPTPermissions(permissions),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := token.SignedString(as.privateKey)
	if err != nil {
		return "", err
	}

	as.mu.Lock()
	as.rpts[signed] = &RPT{
		Token:       signed,
		Permissions: permissions,
		ExpiresAt:   now.Add(1 * time.Hour),
	}
	as.mu.Unlock()

	return signed, nil
}

func toRPTPermissions(perms []Permission) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(perms))
	for _, perm := range perms {
		result = append(result, map[string]interface{}{
			"resource_id":     perm.ResourceID,
			"resource_scopes": perm.Scopes,
		})
	}
	return result
}

// evaluatePolicy checks if access should be granted based on policy
func (as *UMAAuthorizationServer) evaluatePolicy(resourceID, webID string, requestedScopes []string) bool {
	as.mu.RLock()
	defer as.mu.RUnlock()

	policy, exists := as.policies[resourceID]
	if !exists {
		return false // No policy = deny by default
	}

	for _, rule := range policy.Rules {
		if as.matchesRule(rule, webID, requestedScopes) {
			return rule.Effect == "allow"
		}
	}

	return false
}

func (as *UMAAuthorizationServer) matchesRule(rule PolicyRule, webID string, requestedScopes []string) bool {
	// Check if subject matches
	subjectMatches := false
	for _, subject := range rule.Subjects {
		if subject == webID || subject == "*" {
			subjectMatches = true
			break
		}
	}

	if !subjectMatches {
		return false
	}

	// Check if all requested scopes are in rule scopes
	for _, requestedScope := range requestedScopes {
		found := false
		for _, ruleScope := range rule.Scopes {
			if ruleScope == requestedScope || ruleScope == "*" {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// generateRPT creates a new RPT token
func (as *UMAAuthorizationServer) generateRPT(permissions []Permission, expiresIn time.Duration) string {
	rpt := generateRandomString(64)

	as.mu.Lock()
	defer as.mu.Unlock()

	as.rpts[rpt] = &RPT{
		Token:       rpt,
		Permissions: permissions,
		ExpiresAt:   time.Now().Add(expiresIn),
	}

	return rpt
}

// ValidateRPT checks if an RPT is valid and returns its permissions
func (as *UMAAuthorizationServer) ValidateRPT(rpt string) ([]Permission, bool) {
	as.mu.RLock()
	defer as.mu.RUnlock()

	token, exists := as.rpts[rpt]
	if !exists {
		return nil, false
	}

	if time.Now().After(token.ExpiresAt) {
		return nil, false
	}

	return token.Permissions, true
}
