package integration_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"aggregator-integration-test/mocks"
	"github.com/google/uuid"
)

func TestMultipleAggregators_SameUser(t *testing.T) {
	// TODO: Test creating multiple aggregators for same user
	// 1. Create aggregator A for user
	// 2. Create aggregator B for same user
	// 3. Verify both work independently
	// 4. Verify token updates affect correct aggregator
	// 5. Verify deletion only affects targeted aggregator
}

func TestAggregator_TokenRefresh(t *testing.T) {
	// TODO: Test automatic token refresh using refresh_token
	// 1. Create aggregator with short-lived access token
	// 2. Wait for token expiration
	// 3. Trigger aggregator to access upstream resource
	// 4. Verify aggregator uses refresh token to get new access token
	// 5. Verify operation succeeds with new token
}

func TestAggregator_RefreshToken_Expired(t *testing.T) {
	// TODO: Test when both access and refresh tokens expire
	// 1. Create aggregator
	// 2. Mock expiration of both tokens
	// 3. Verify aggregator operations fail appropriately
	// 4. Verify login_status becomes false
	// 5. Verify token update flow can recover
}

func TestService_ConcurrentAccess(t *testing.T) {
	// TODO: Test concurrent access to same service
	// 1. Create service
	// 2. Spawn multiple goroutines accessing service simultaneously
	// 3. Verify all requests succeed
	// 4. Verify no race conditions in UMA token management
}

func TestService_LocationURL_Protection(t *testing.T) {
	// TODO: Test that service location URLs are properly protected
	// 1. Create service
	// 2. Attempt to access location URL without authorization
	// 3. Verify 401 Unauthorized with UMA ticket
	// 4. Verify proper UMA flow required
}

func TestAggregator_URLPatterns(t *testing.T) {
	// TODO: Test both host-based and path-based instance addressing
	// 1. If server supports host-based: verify https://{id}.aggregator.example/
	// 2. If server supports path-based: verify https://aggregator.example/{id}/
	// 3. Verify all returned URLs use consistent pattern for same instance
	// 4. Verify clients shouldn't construct URLs by string concatenation
}

func TestWebID_Profile_Provision(t *testing.T) {
	// TODO: Test WebID Profile requirements for provision flow
	// 1. Create aggregator using provision flow
	// 2. Dereference aggregator WebID
	// 3. Verify it conforms to WebID Profile specification
	// 4. Verify it includes solid:oidcIssuer
	// 5. Verify aggregator description IS the WebID document
}

func TestFnO_ExecutionValidation(t *testing.T) {
	// TODO: Test validation of FnO execution descriptions
	// 1. POST service with valid fno:Execution
	// 2. Verify fno:executes points to valid transformation
	// 3. Test with missing required parameters - verify 400
	// 4. Test with wrong parameter types - verify 400
	// 5. Test with fno:Composition (pre-defined pipelines)
	// 6. Test with external functions via rdfs:seeAlso
}

func TestSpecVersion_Compatibility(t *testing.T) {
	// TODO: Test spec version handling
	// 1. Verify server advertises version in server description
	// 2. Test client behavior with different version values
	// 3. Verify semantic versioning compatibility rules
}

func TestInstance_NamespaceNotFound(t *testing.T) {
	namespace := "missing-" + uuid.NewString()
	url := fmt.Sprintf("%s/config/%s", testEnv.AggregatorURL, namespace)

	assertNotFoundOrUnauthorized(t, url)
}

func TestInstance_Transformations_NamespaceNotFound(t *testing.T) {
	namespace := "missing-" + uuid.NewString()
	url := fmt.Sprintf("%s/config/%s/transformations", testEnv.AggregatorURL, namespace)

	assertNotFoundOrUnauthorized(t, url)
}

func TestInstance_Services_NamespaceNotFound(t *testing.T) {
	namespace := "missing-" + uuid.NewString()
	url := fmt.Sprintf("%s/config/%s/services", testEnv.AggregatorURL, namespace)

	assertNotFoundOrUnauthorized(t, url)
}

func TestRegistration_Update_NonexistentAggregator(t *testing.T) {
	oidcProvider, err := mocks.NewOIDCProvider()
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}
	defer oidcProvider.Close()

	authToken := createAuthToken(t, oidcProvider, oidcProvider.URL()+"/webid#me")
	body := map[string]interface{}{
		"registration_type": "client_credentials",
		"aggregator_id":     "agg-" + uuid.NewString(),
	}
	payload, _ := json.Marshal(body)

	req, err := http.NewRequest("POST", testEnv.AggregatorURL+"/registration", bytes.NewBuffer(payload))
	if err != nil {
		t.Fatalf("Failed to create update request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Update request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("Expected 403 Forbidden for unknown aggregator, got %d", resp.StatusCode)
	}
}

func TestRegistration_Delete_NonexistentAggregator(t *testing.T) {
	oidcProvider, err := mocks.NewOIDCProvider()
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}
	defer oidcProvider.Close()

	authToken := createAuthToken(t, oidcProvider, oidcProvider.URL()+"/webid#me")
	body := map[string]interface{}{
		"aggregator_id": "agg-" + uuid.NewString(),
	}
	payload, _ := json.Marshal(body)

	req, err := http.NewRequest("DELETE", testEnv.AggregatorURL+"/registration", bytes.NewBuffer(payload))
	if err != nil {
		t.Fatalf("Failed to create delete request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Delete request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("Expected 403 Forbidden for unknown aggregator, got %d", resp.StatusCode)
	}
}

func assertNotFoundOrUnauthorized(t *testing.T, url string) {
	t.Helper()

	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotFound, http.StatusUnauthorized, http.StatusForbidden:
		return
	case http.StatusOK:
		t.Fatalf("Expected non-200 status for unknown namespace, got %d", resp.StatusCode)
	default:
		t.Fatalf("Unexpected status for unknown namespace: %d", resp.StatusCode)
	}
}
