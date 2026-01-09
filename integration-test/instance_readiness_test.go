package integration_test

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"aggregator-integration-test/mocks"
)

func TestInstanceDescription_ReturnsServiceUnavailableWhileStarting(t *testing.T) {
	oidcProvider, err := mocks.NewOIDCProvider()
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}
	defer oidcProvider.Close()

	ownerWebID := oidcProvider.URL() + "/webid#me"
	authToken := createAuthToken(t, oidcProvider, ownerWebID)

	aggregatorID := createAggregatorViaNone(t, authToken)
	defer deleteAggregator(t, aggregatorID, authToken)

	namespace := waitForAggregatorNamespace(t, ownerWebID)
	baseURL := fmt.Sprintf("%s/config/%s", testEnv.AggregatorURL, namespace)

	client := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet, strings.TrimRight(baseURL, "/"), nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusServiceUnavailable {
			return
		}
		if resp.StatusCode == http.StatusOK {
			t.Skip("Instance became ready before observing 503")
		}
		if resp.StatusCode == http.StatusNotFound {
			t.Fatalf("Expected 503 before ready, got 404: %s", string(bodyBytes))
		}
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("Expected 503 before ready, got %d: %s", resp.StatusCode, string(bodyBytes))
		}

		time.Sleep(1 * time.Second)
	}

	t.Fatalf("Timed out waiting for 503 from %s before ready", baseURL)
}
