package mocks

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"
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
	derivationHandles map[string]*DerivationHandle
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

// NewUMAAuthorizationServer creates a new mock UMA AS
func NewUMAAuthorizationServer() *UMAAuthorizationServer {
	as := &UMAAuthorizationServer{
		resources:         make(map[string]*UMAResource),
		tickets:           make(map[string]*UMATicket),
		rpts:              make(map[string]*RPT),
		policies:          make(map[string]*Policy),
		derivationHandles: make(map[string]*DerivationHandle),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/uma2-configuration", as.handleUMAConfiguration)
	mux.HandleFunc("/resource_set", as.handleResourceRegistration)
	mux.HandleFunc("/permission", as.handlePermissionRequest)
	mux.HandleFunc("/token", as.handleTokenRequest)
	mux.HandleFunc("/introspect", as.handleRPTIntrospection)
	mux.HandleFunc("/policy", as.handlePolicyManagement)

	as.server = httptest.NewServer(mux)
	as.issuer = as.server.URL

	return as
}

// Close shuts down the mock server
func (as *UMAAuthorizationServer) Close() {
	as.server.Close()
}

// URL returns the base URL of the mock UMA AS
func (as *UMAAuthorizationServer) URL() string {
	return as.server.URL
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
		"grant_types_supported":                 []string{"urn:ietf:params:oauth:grant-type:uma-ticket"},
		"uma_profiles_supported":                []string{"uma_2_0"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

func (as *UMAAuthorizationServer) handleResourceRegistration(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement resource registration endpoint
	// POST: Create new resource
	// PUT: Update existing resource
	// DELETE: Delete resource
	// GET: Retrieve resource details
	// Handles resource_relations for derivation tracking
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func (as *UMAAuthorizationServer) handlePermissionRequest(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement permission request endpoint (ticket generation)
	// 1. Parse permission request (resource_id, resource_scopes)
	// 2. Generate UMA ticket
	// 3. Store ticket with resource and scopes
	// 4. Return ticket in response
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func (as *UMAAuthorizationServer) handleTokenRequest(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")

	if grantType == "urn:ietf:params:oauth:grant-type:uma-ticket" {
		as.handleUMATicketGrant(w, r)
	} else {
		http.Error(w, "Unsupported grant type", http.StatusBadRequest)
	}
}

func (as *UMAAuthorizationServer) handleUMATicketGrant(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement UMA ticket grant (RPT issuance)
	// 1. Extract ticket from request
	// 2. Extract claim_tokens (ID tokens, access tokens)
	// 3. Validate ticket exists and not expired
	// 4. Evaluate policies for resource access
	// 5. If derivation scope requested, check derivation-creation scope and issue derivation_resource_id
	// 6. If access depends on upstream resources, return need_info with required_claims
	// 7. Validate upstream access tokens if provided
	// 8. If all checks pass, issue RPT with permissions
	http.Error(w, "Not implemented", http.StatusNotImplemented)
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
	// TODO: Implement policy management endpoint
	// 1. Authenticate resource owner
	// 2. GET: retrieve policies for resource
	// 3. PUT: update policies
	// 4. DELETE: delete policies
	http.Error(w, "Not implemented", http.StatusNotImplemented)
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
