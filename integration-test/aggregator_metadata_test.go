package integration_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAggregatorDescription(t *testing.T) {
	instance := setupAggregatorInstance(t)
	defer instance.cleanup()

	desc := fetchAggregatorDescription(t, instance.baseURL, instance.authToken)

	if desc.CreatedAt == "" {
		t.Fatal("created_at is missing")
	}
	if _, err := time.Parse(time.RFC3339, desc.CreatedAt); err != nil {
		t.Fatalf("created_at is not RFC3339: %v", err)
	}

	if desc.TransformationCatalog == "" {
		t.Fatal("transformation_catalog is missing")
	}
	if !isAbsoluteURL(desc.TransformationCatalog) {
		t.Fatalf("transformation_catalog is not absolute: %s", desc.TransformationCatalog)
	}
	if !strings.HasSuffix(desc.TransformationCatalog, "/transformations") {
		t.Fatalf("transformation_catalog has unexpected path: %s", desc.TransformationCatalog)
	}

	if desc.ServiceCollection == "" {
		t.Fatal("service_collection is missing")
	}
	if !isAbsoluteURL(desc.ServiceCollection) {
		t.Fatalf("service_collection is not absolute: %s", desc.ServiceCollection)
	}
	expectedServicePath := fmt.Sprintf("/config/%s/services", instance.namespace)
	if !strings.Contains(desc.ServiceCollection, expectedServicePath) {
		t.Fatalf("service_collection missing expected path %s: %s", expectedServicePath, desc.ServiceCollection)
	}

	if desc.ID != "" && !isAbsoluteURL(desc.ID) {
		t.Fatalf("id is not absolute: %s", desc.ID)
	}

	if desc.TokenExpiry != "" {
		if _, err := time.Parse(time.RFC3339, desc.TokenExpiry); err != nil {
			t.Fatalf("token_expiry is not RFC3339: %v", err)
		}
	}
}

func TestAggregatorDescription_AuthoritativeEndpoints(t *testing.T) {
	instance := setupAggregatorInstance(t)
	defer instance.cleanup()

	desc := fetchAggregatorDescription(t, instance.baseURL, instance.authToken)
	baseURL := strings.TrimRight(instance.baseURL, "/")

	if desc.ID != "" && desc.ID != baseURL {
		t.Fatalf("id does not match base URL: %s", desc.ID)
	}
	if desc.TransformationCatalog != baseURL+"/transformations" {
		t.Fatalf("transformation_catalog does not match base URL: %s", desc.TransformationCatalog)
	}
	if desc.ServiceCollection != baseURL+"/services" {
		t.Fatalf("service_collection does not match base URL: %s", desc.ServiceCollection)
	}
}

func TestAggregatorDescription_CreatedAtStable(t *testing.T) {
	instance := setupAggregatorInstance(t)
	defer instance.cleanup()

	desc := fetchAggregatorDescription(t, instance.baseURL, instance.authToken)
	time.Sleep(1 * time.Second)
	descAgain := fetchAggregatorDescription(t, instance.baseURL, instance.authToken)

	if desc.CreatedAt != descAgain.CreatedAt {
		t.Fatalf("created_at should be stable, got %s then %s", desc.CreatedAt, descAgain.CreatedAt)
	}
}

func TestAggregatorDescription_NoneFlowLoginStatus(t *testing.T) {
	instance := setupAggregatorInstanceNone(t)
	defer instance.cleanup()

	desc := fetchAggregatorDescription(t, instance.baseURL, instance.authToken)
	if desc.LoginStatus {
		t.Fatal("login_status should be false for none flow")
	}
	if desc.TokenExpiry != "" {
		t.Fatalf("token_expiry should be empty for none flow, got %s", desc.TokenExpiry)
	}
}

func TestAggregatorDescription_LoginStatusExpired(t *testing.T) {
	instance := setupAggregatorInstance(t)
	defer instance.cleanup()

	expired := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cm, err := testEnv.KubeClient.CoreV1().ConfigMaps(instance.namespace).Get(ctx, "aggregator-instance-config", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Failed to get instance configmap: %v", err)
	}
	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	cm.Data["access_token_expiry"] = expired
	if _, err := testEnv.KubeClient.CoreV1().ConfigMaps(instance.namespace).Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("Failed to update instance configmap: %v", err)
	}

	desc := fetchAggregatorDescription(t, instance.baseURL, instance.authToken)
	if desc.LoginStatus {
		t.Fatal("login_status should be false for expired tokens")
	}
	if desc.TokenExpiry != expired {
		t.Fatalf("token_expiry mismatch, expected %s, got %s", expired, desc.TokenExpiry)
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
