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

// --- With Auth Server --- //
func TestAuthenticateRequest_DisableAuth_AuthServer_StdOIDC(t *testing.T) {
	originalDisableAuth := model.DisableAuth
	originalAuthServer := model.AuthServer

	defer func() {
		model.DisableAuth = originalDisableAuth
		model.AuthServer = originalAuthServer
	}()

	model.DisableAuth = true
	model.AuthServer = "https://auth.example"

	// Create a simple JWT token with subject claim
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "alice@exmaple.com",
		"iss": "https://auth.example",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString([]byte("test-secret"))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	issuer, id, mode, err := authenticateRequest(req)
	if err != nil {
		t.Fatalf("Expected no error with disable_auth=true, got: %v", err)
	}
	if issuer != "https://auth.example" {
		t.Errorf("Expected issuer 'https://auth.example', got '%s'", issuer)
	}
	if id != "alice@exmaple.com" {
		t.Errorf("Expected ID 'alice@exmaple.com', got '%s'", id)
	}
	if mode != "oidc" {
		t.Errorf("Expected mode 'oidc', got '%s'", mode)
	}
}

func TestAuthenticateRequest_DisableAuth_AuthServer_SolidOIDC(t *testing.T) {
	originalDisableAuth := model.DisableAuth
	originalAuthServer := model.AuthServer

	defer func() {
		model.DisableAuth = originalDisableAuth
		model.AuthServer = originalAuthServer
	}()

	model.DisableAuth = true
	model.AuthServer = "https://auth.example"

	// Create token with 'sub' claim
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "https://alice.example/webid#me",
		"iss": "https://solid-auth.example",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString([]byte("test-secret"))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	issuer, id, mode, err := authenticateRequest(req)

	if err != nil {
		t.Fatalf("Expected no error with disable_auth=true, got: %v", err)
	}
	if issuer != "https://solid-auth.example" {
		t.Errorf("Expected issuer 'https://solid-auth.example', got '%s'", issuer)
	}
	if id != "https://alice.example/webid#me" {
		t.Errorf("Expected ID 'https://alice.example/webid#me', got '%s'", id)
	}
	if mode != "solid-oidc" {
		t.Errorf("Expected mode 'solid-oidc', got '%s'", mode)
	}
}

// --- Without auth server --- //
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

	issuer, id, mode, err := authenticateRequest(req)

	if err != nil {
		t.Fatalf("Expected no error with disable_auth=true, got: %v", err)
	}
	if issuer != "https://idp.example" {
		t.Errorf("Expected issuer 'https://idp.example', got '%s'", issuer)
	}
	if id != "https://alice.example/webid#me" {
		t.Errorf("Expected WebID 'https://alice.example/webid#me', got '%s'", id)
	}
	if mode != "solid-oidc" {
		t.Errorf("Expected mode 'solid-oidc', got '%s'", mode)
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

	issuer, id, mode, err := authenticateRequest(req)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if issuer != "https://idp.example" {
		t.Errorf("Expected issuer 'https://idp.example', got '%s'", issuer)
	}
	if id != "https://bob.example/webid#me" {
		t.Errorf("Expected WebID from 'sub' claim, got '%s'", id)
	}
	if mode != "solid-oidc" {
		t.Errorf("Expected mode 'solid-oidc', got '%s'", mode)
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

	_, _, _, err := authenticateRequest(req)

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

	_, _, _, err := authenticateRequest(req)

	if err == nil {
		t.Fatal("Expected error for invalid JWT format")
	}
}

// Note: Testing full token validation (model.DisableAuth=false) requires setting up
// a mock OIDC provider with JWKS endpoint, which is more appropriate for integration tests
// The unit tests above verify the disable_auth bypass logic works correctly
