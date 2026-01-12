package mocks

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

// ResourceServer mocks a UMA-protected Resource Server
type ResourceServer struct {
	server         *httptest.Server
	authServer     *UMAAuthorizationServer
	mu             sync.RWMutex
	resources      map[string]*Resource
	protectedPaths map[string]string // path -> resourceID
}

type Resource struct {
	ID       string
	Path     string
	Content  interface{}
	MimeType string
	Owner    string
	Scopes   []string
}

// NewResourceServer creates a new mock resource server
func NewResourceServer(authServer *UMAAuthorizationServer) *ResourceServer {
	rs := &ResourceServer{
		authServer:     authServer,
		resources:      make(map[string]*Resource),
		protectedPaths: make(map[string]string),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", rs.handleRequest)

	rs.server = httptest.NewServer(mux)

	return rs
}

// Close shuts down the mock server
func (rs *ResourceServer) Close() {
	rs.server.Close()
}

// URL returns the base URL of the mock resource server
func (rs *ResourceServer) URL() string {
	return rs.server.URL
}

// AddResource adds a protected resource to the server
func (rs *ResourceServer) AddResource(path, resourceID, owner string, content interface{}, mimeType string, scopes []string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	rs.resources[resourceID] = &Resource{
		ID:       resourceID,
		Path:     path,
		Content:  content,
		MimeType: mimeType,
		Owner:    owner,
		Scopes:   scopes,
	}
	rs.protectedPaths[path] = resourceID

	// Register resource with authorization server
	rs.authServer.RegisterResource(resourceID, "Resource at "+path, owner, scopes)
}

// RemoveResource removes a resource from the server
func (rs *ResourceServer) RemoveResource(resourceID string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if resource, exists := rs.resources[resourceID]; exists {
		delete(rs.protectedPaths, resource.Path)
		delete(rs.resources, resourceID)
	}
}

func (rs *ResourceServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	rs.mu.RLock()
	resourceID, exists := rs.protectedPaths[path]
	rs.mu.RUnlock()

	if !exists {
		http.NotFound(w, r)
		return
	}

	rs.mu.RLock()
	resource := rs.resources[resourceID]
	rs.mu.RUnlock()

	// Extract authorization header
	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {
		// No token provided, issue UMA ticket
		rs.issueUMATicket(w, resourceID, resource.Scopes)
		return
	}

	// Extract bearer token
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == authHeader {
		http.Error(w, "Invalid authorization header", http.StatusUnauthorized)
		return
	}

	// Validate RPT with authorization server
	permissions, valid := rs.authServer.ValidateRPT(token)
	if !valid {
		// Invalid token, issue new ticket
		rs.issueUMATicket(w, resourceID, resource.Scopes)
		return
	}

	// Check if RPT has permission for this resource
	if !rs.hasPermission(permissions, resourceID, resource.Scopes) {
		// Insufficient permissions, issue ticket
		rs.issueUMATicket(w, resourceID, resource.Scopes)
		return
	}

	// Access granted, serve the resource
	rs.serveResource(w, r, resource)
}

func (rs *ResourceServer) issueUMATicket(w http.ResponseWriter, resourceID string, scopes []string) {
	// TODO: Request ticket from authorization server
	// For now, return a mock UMA challenge

	ticket := generateRandomString(32)

	// Store ticket in AS (simplified - should call AS API)
	rs.authServer.mu.Lock()
	rs.authServer.tickets[ticket] = &UMATicket{
		Ticket:     ticket,
		ResourceID: resourceID,
		Scopes:     scopes,
		ExpiresAt:  time.Now().Add(5 * time.Minute),
	}
	rs.authServer.mu.Unlock()

	w.Header().Set("WWW-Authenticate", fmt.Sprintf(
		`UMA realm="resource_server", as_uri="%s", ticket="%s"`,
		rs.authServer.URL(),
		ticket,
	))
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             "unauthorized",
		"error_description": "Authorization required",
	})
}

func (rs *ResourceServer) hasPermission(permissions []Permission, resourceID string, requiredScopes []string) bool {
	for _, perm := range permissions {
		if perm.ResourceID == resourceID {
			// Check if all required scopes are present
			for _, required := range requiredScopes {
				found := false
				for _, granted := range perm.Scopes {
					if granted == required || granted == "*" {
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
	}
	return false
}

func (rs *ResourceServer) serveResource(w http.ResponseWriter, r *http.Request, resource *Resource) {
	w.Header().Set("Content-Type", resource.MimeType)

	switch content := resource.Content.(type) {
	case string:
		w.Write([]byte(content))
	case []byte:
		w.Write(content)
	case map[string]interface{}, []interface{}:
		json.NewEncoder(w).Encode(content)
	default:
		json.NewEncoder(w).Encode(content)
	}
}
