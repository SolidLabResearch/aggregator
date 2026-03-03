package integration_test

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestAggregatorDescription_LoginStatusExpired(t *testing.T) {
	instance := setupAggregatorInstance(t)
	defer instance.cleanup()

	// TODO: How to simulate an expired token?

	desc := fetchAggregatorDescription(t, instance.baseURL, instance.authToken)
	if desc.LoginStatus {
		t.Fatal("login_status should be false for expired tokens")
	}
}

func TestAggregatorDescription_Unauthenticated(t *testing.T) {
	instance := setupAggregatorInstance(t)
	defer instance.cleanup()

	resp, err := http.Get(strings.TrimRight(instance.baseURL, "/"))
	if err != nil {
		t.Fatalf("Failed to fetch aggregator description: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		t.Logf("Unauthenticated access rejected with status %d", resp.StatusCode)
		return
	}
	t.Fatalf("Expected 401/403 for unauthenticated access, got %d", resp.StatusCode)
}

func TestAggregatorDescription_LoginStatus(t *testing.T) {
	instance := setupAggregatorInstance(t)
	defer instance.cleanup()

	desc := fetchAggregatorDescription(t, instance.baseURL, instance.authToken)
	if !desc.LoginStatus {
		t.Fatal("login_status is false")
	}
	if desc.TokenExpiry == "" {
		t.Fatal("token_expiry is missing")
	}
	if _, err := time.Parse(time.RFC3339, desc.TokenExpiry); err != nil {
		t.Fatalf("token_expiry is not RFC3339: %v", err)
	}
}

func TestInstanceTransformationCatalog(t *testing.T) {
	instance := setupAggregatorInstance(t)
	defer instance.cleanup()

	desc := fetchAggregatorDescription(t, instance.baseURL, instance.authToken)

	resp, bodyBytes := getWithUMA(t, desc.TransformationCatalog, instance.authToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d: %s", resp.StatusCode, string(bodyBytes))
	}

	contentType := resp.Header.Get("Content-Type")
	if !containsContentType(contentType, "text/turtle") {
		t.Fatalf("Expected text/turtle content-type, got %s", contentType)
	}
}
