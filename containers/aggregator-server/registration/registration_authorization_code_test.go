package registration

import (
	"aggregator/model"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestValidateRedirectURI_AllowsWhenNoRedirectURIs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"client_id": "https://example.com/client.json",
		})
	}))
	defer server.Close()

	if err := validateRedirectURI("https://app.example/callback", server.URL); err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
}

func TestValidateRedirectURI_AllowsRegisteredRedirectURI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"client_id":     "https://example.com/client.json",
			"redirect_uris": []string{"https://app.example/callback"},
		})
	}))
	defer server.Close()

	if err := validateRedirectURI("https://app.example/callback", server.URL); err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
}

func TestValidateRedirectURI_RejectsUnregisteredRedirectURI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"client_id":     "https://example.com/client.json",
			"redirect_uris": []string{"https://app.example/callback"},
		})
	}))
	defer server.Close()

	if err := validateRedirectURI("https://app.example/other", server.URL); err == nil {
		t.Fatal("Expected error for unregistered redirect URI")
	}
}

func TestValidateRedirectURI_MultipleURIs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"client_id":     "https://example.com/client.json",
			"redirect_uris": []string{"https://app.example/callback1", "https://app.example/callback2"},
		})
	}))
	defer server.Close()

	if err := validateRedirectURI("https://app.example/callback2", server.URL); err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
}

func TestHandleAuthorizationCodeFinish_AllowsMissingOptionalTokenFields(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token": "access-token",
		})
	}))
	defer tokenServer.Close()

	originalClientID := model.ClientId
	originalClientSecret := model.ClientSecret
	model.ClientId = "http://aggregator.local/client.json"
	model.ClientSecret = "test-secret"
	t.Cleanup(func() {
		model.ClientId = originalClientID
		model.ClientSecret = originalClientSecret
	})

	instance := createAggregatorInstanceRecord(
		"https://owner.example/webid#me",
		"authorization_code",
		"https://as.example",
		"ns-test",
		"access",
		"refresh",
	)

	state := "state-missing-fields"
	stateStoreMu.Lock()
	stateStore[state] = storedState{
		OwnerWebID:          instance.OwnerWebID,
		AuthorizationServer: instance.AuthorizationServer,
		AggregatorID:        instance.AggregatorID,
		CodeVerifier:        "verifier",
		TokenEndpoint:       tokenServer.URL,
		ExpiresAt:           time.Now().Add(time.Minute),
	}
	stateStoreMu.Unlock()
	t.Cleanup(func() {
		stateStoreMu.Lock()
		delete(stateStore, state)
		stateStoreMu.Unlock()
		_ = deleteAggregatorInstance(instance.AggregatorID)
	})

	req := model.RegistrationRequest{
		RegistrationType: "authorization_code",
		Code:             "auth-code",
		RedirectURI:      "https://app.example/callback",
		State:            state,
	}

	rec := httptest.NewRecorder()
	handleAuthorizationCodeFinish(rec, req, instance.OwnerWebID)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d", rec.Code)
	}
}

func TestHandleAuthorizationCodeFinish_UsesStoredClientIDForRedirectValidation(t *testing.T) {
	redirectURI := "https://app.example/callback"

	allowedClientServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"client_id":     "https://app.example/client.json",
			"redirect_uris": []string{redirectURI},
		})
	}))
	defer allowedClientServer.Close()

	otherClientServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"client_id":     "https://other.example/client.json",
			"redirect_uris": []string{"https://other.example/callback"},
		})
	}))
	defer otherClientServer.Close()

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token": "access-token",
		})
	}))
	defer tokenServer.Close()

	originalClientID := model.ClientId
	originalClientSecret := model.ClientSecret
	model.ClientId = otherClientServer.URL
	model.ClientSecret = "test-secret"
	t.Cleanup(func() {
		model.ClientId = originalClientID
		model.ClientSecret = originalClientSecret
	})

	instance := createAggregatorInstanceRecord(
		"https://owner.example/webid#me",
		"authorization_code",
		"https://as.example",
		"ns-test",
		"access",
		"refresh",
	)

	state := "state-redirect-validation"
	stateStoreMu.Lock()
	stateStore[state] = storedState{
		OwnerWebID:          instance.OwnerWebID,
		AuthorizationServer: instance.AuthorizationServer,
		AggregatorID:        instance.AggregatorID,
		ClientID:            allowedClientServer.URL,
		CodeVerifier:        "verifier",
		TokenEndpoint:       tokenServer.URL,
		ExpiresAt:           time.Now().Add(time.Minute),
	}
	stateStoreMu.Unlock()
	t.Cleanup(func() {
		stateStoreMu.Lock()
		delete(stateStore, state)
		stateStoreMu.Unlock()
		_ = deleteAggregatorInstance(instance.AggregatorID)
	})

	req := model.RegistrationRequest{
		RegistrationType: "authorization_code",
		Code:             "auth-code",
		RedirectURI:      redirectURI,
		State:            state,
	}

	rec := httptest.NewRecorder()
	handleAuthorizationCodeFinish(rec, req, instance.OwnerWebID)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d", rec.Code)
	}
}
