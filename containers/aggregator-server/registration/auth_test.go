package registration

import (
	"aggregator/model"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestExtractBearerToken_Success(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer test-token-123")

	token, err := extractBearerToken(req)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if token != "test-token-123" {
		t.Errorf("Expected 'test-token-123', got '%s'", token)
	}
}

func TestExtractBearerToken_Missing(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)

	_, err := extractBearerToken(req)

	if err == nil {
		t.Fatal("Expected error for missing Authorization header")
	}
}

func TestExtractBearerToken_InvalidFormat(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Basic invalid")

	_, err := extractBearerToken(req)

	if err == nil {
		t.Fatal("Expected error for non-Bearer auth")
	}
}

func TestAuthenticateRequest_DisabledAuth(t *testing.T) {
	// Save original state and restore after test
	originalDisableAuth := model.DisableAuth
	defer func() { model.DisableAuth = originalDisableAuth }()

	// Enable test mode
	model.DisableAuth = true

	// Create a simple JWT token with WebID claim
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"webid": "https://alice.example/webid#me",
		"iss":   "https://idp.example",
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString([]byte("test-secret"))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	webID, err := authenticateRequest(req)

	if err != nil {
		t.Fatalf("Expected no error with disable_auth=true, got: %v", err)
	}
	if webID != "https://alice.example/webid#me" {
		t.Errorf("Expected WebID 'https://alice.example/webid#me', got '%s'", webID)
	}
}

func TestAuthenticateRequest_DisabledAuth_UsesSubClaim(t *testing.T) {
	// Save original state
	originalDisableAuth := model.DisableAuth
	defer func() { model.DisableAuth = originalDisableAuth }()

	model.DisableAuth = true

	// Create token with 'sub' claim instead of 'webid'
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "https://bob.example/webid#me",
		"iss": "https://idp.example",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString([]byte("test-secret"))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	webID, err := authenticateRequest(req)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if webID != "https://bob.example/webid#me" {
		t.Errorf("Expected WebID from 'sub' claim, got '%s'", webID)
	}
}

func TestAuthenticateRequest_DisabledAuth_NoWebID(t *testing.T) {
	originalDisableAuth := model.DisableAuth
	defer func() { model.DisableAuth = originalDisableAuth }()

	model.DisableAuth = true

	// Create token without webid or sub claim
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "https://idp.example",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString([]byte("test-secret"))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	_, err := authenticateRequest(req)

	if err == nil {
		t.Fatal("Expected error when token has no webid or sub claim")
	}
}

func TestAuthenticateRequest_DisabledAuth_InvalidToken(t *testing.T) {
	originalDisableAuth := model.DisableAuth
	defer func() { model.DisableAuth = originalDisableAuth }()

	model.DisableAuth = true

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer invalid-jwt-token")

	_, err := authenticateRequest(req)

	if err == nil {
		t.Fatal("Expected error for invalid JWT format")
	}
}

func TestAuthenticateRequest_DisabledAuth_MissingAuthorization(t *testing.T) {
	originalDisableAuth := model.DisableAuth
	defer func() { model.DisableAuth = originalDisableAuth }()

	model.DisableAuth = true

	req := httptest.NewRequest("GET", "/", nil)
	webID, err := authenticateRequest(req)
	if err != nil {
		t.Fatalf("Expected no error when auth is disabled, got: %v", err)
	}
	if webID != "" {
		t.Fatalf("Expected empty WebID when Authorization is missing, got %q", webID)
	}
}

// Note: Testing full token validation (model.DisableAuth=false) requires setting up
// a mock OIDC provider with JWKS endpoint, which is more appropriate for integration tests
// The unit tests above verify the disable_auth bypass logic works correctly
