package integration_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

func TestServiceCollection_Head(t *testing.T) {
	instance := setupAggregatorInstance(t)
	defer instance.cleanup()

	desc := fetchAggregatorDescription(t, instance.baseURL, instance.authToken)

	resp, bodyBytes := doWithUMA(t, http.MethodHead, desc.ServiceCollection, instance.authToken, nil, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d: %s", resp.StatusCode, string(bodyBytes))
	}

	contentType := resp.Header.Get("Content-Type")
	if !containsContentType(contentType, "application/json") {
		t.Fatalf("Expected application/json content-type, got %s", contentType)
	}

	if resp.Header.Get("ETag") == "" {
		t.Fatal("Expected ETag header for service collection")
	}

	if len(bodyBytes) != 0 {
		t.Fatalf("Expected empty body for HEAD, got %q", string(bodyBytes))
	}
}

func TestServiceCollection_Get_Empty(t *testing.T) {
	instance := setupAggregatorInstance(t)
	defer instance.cleanup()

	desc := fetchAggregatorDescription(t, instance.baseURL, instance.authToken)

	resp, bodyBytes := getWithUMA(t, desc.ServiceCollection, instance.authToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d: %s", resp.StatusCode, string(bodyBytes))
	}

	contentType := resp.Header.Get("Content-Type")
	if !containsContentType(contentType, "application/json") {
		t.Fatalf("Expected application/json content-type, got %s", contentType)
	}

	if resp.Header.Get("ETag") == "" {
		t.Fatal("Expected ETag header for service collection")
	}

	var actors []map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &actors); err != nil {
		t.Fatalf("Failed to decode service collection: %v", err)
	}
	if len(actors) != 0 {
		t.Fatalf("Expected empty service collection, got %d items", len(actors))
	}
}

func TestServiceCollection_Get_WithServices(t *testing.T) {
	// TODO: Test GET service collection with existing services
	// 1. Create aggregator and add multiple services
	// 2. GET service_collection
	// 3. Verify services array contains absolute URLs
	// 4. Verify each URL is dereferenceable
	// 5. Verify content negotiation works
}

func TestServiceCollection_ETagChanges(t *testing.T) {
	// TODO: Test ETag changes when services are added/removed
	// 1. GET collection and store ETag
	// 2. Add a service
	// 3. GET collection again, verify ETag changed
	// 4. Delete the service
	// 5. GET collection again, verify ETag changed again
}

func TestServiceCollection_Post_CreateSimpleService(t *testing.T) {
	// TODO: Test § 8.1 POST to create service
	// 1. Create aggregator instance
	// 2. Get transformation catalog and pick a transformation
	// 3. Create FnO execution description (Turtle or JSON-LD)
	// 4. Mock UMA authentication with 'create' scope
	// 5. POST execution to service_collection endpoint
	// 6. Verify 201 Created response
	// 7. Verify response body includes full service representation
	// 8. Verify service has: id, status, transformation, created_at, location
	// 9. Verify new UMA resource registered for service with read/delete scopes
}

func TestServiceCollection_Post_WithUpstreamSources(t *testing.T) {
	// TODO: Test creating service that accesses upstream resources
	// 1. Create aggregator instance
	// 2. Create FnO execution with upstream resource URLs as inputs
	// 3. Mock upstream resource servers and their UMA AS
	// 4. POST service creation
	// 5. Verify aggregator performs UMA flow to upstream AS
	// 6. Verify aggregator requests derivation-creation scope
	// 7. Verify aggregator receives derivation_resource_id
	// 8. Verify aggregator registers resource_relations with prov:wasDerivedFrom
	// 9. Verify service location is accessible
}

func TestServiceCollection_Post_InvalidExecution(t *testing.T) {
	// TODO: Test POST with invalid FnO execution
	// 1. POST with malformed FnO description
	// 2. POST with non-existent transformation reference
	// 3. POST with missing required parameters
	// 4. Verify 400 Bad Request responses
}

func TestServiceCollection_Post_ServiceInstantiationFailure(t *testing.T) {
	// TODO: Test POST when service cannot be instantiated
	// 1. Create valid FnO execution
	// 2. Mock upstream resources to be unavailable
	// 3. Verify 500 Internal Server Error
}

func TestServiceCollection_Post_Unauthenticated(t *testing.T) {
	instance := setupAggregatorInstance(t)
	defer instance.cleanup()

	desc := fetchAggregatorDescription(t, instance.baseURL, instance.authToken)

	req, err := http.NewRequest(http.MethodPost, desc.ServiceCollection, bytes.NewBufferString(`{}`))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Unauthenticated request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		t.Fatalf("Expected 401/403 for unauthenticated POST, got %d", resp.StatusCode)
	}
}

func TestServiceCollection_CorsPreFlight(t *testing.T) {
	// TODO: Test CORS preflight for service collection
	// 1. OPTIONS request to service_collection
	// 2. Verify 204 No Content
	// 3. Verify Access-Control-Allow-* headers present
	// 4. Verify Authorization in Access-Control-Allow-Headers
}

func TestServiceResource_Head(t *testing.T) {
	// TODO: Test § 8.2 HEAD individual service
	// 1. Create service
	// 2. HEAD to service URL with UMA authentication
	// 3. Verify 200 OK with ETag and Content-Type headers
	// 4. Verify ETag changes when service state changes
}

func TestServiceResource_Get(t *testing.T) {
	// TODO: Test GET individual service
	// 1. Create service
	// 2. GET service URL with UMA authentication
	// 3. Verify 200 OK with JSON representation
	// 4. Verify required fields: id, status, transformation, created_at, location
	// 5. Verify @type is aggr:Service in RDF representations
	// 6. Verify content negotiation works
}

func TestServiceResource_Get_StatusValues(t *testing.T) {
	// TODO: Test different service status values
	// 1. Create service and verify status: "running"
	// 2. Trigger service restart, verify status: "restarting"
	// 3. Stop service, verify status: "stopped"
	// 4. Cause error condition, verify status: "errored"
}

func TestServiceResource_Delete(t *testing.T) {
	// TODO: Test DELETE service
	// 1. Create service
	// 2. DELETE service URL with UMA authentication (delete scope)
	// 3. Verify 200 OK response
	// 4. Verify service no longer in collection
	// 5. Verify service URL returns 404
	// 6. Verify UMA resource unregistered
	// 7. Verify collection ETag changed
	// 8. Verify service pipeline stopped
	// 9. Verify upstream resource derivation_resource_id cleaned up if needed
}

func TestServiceResource_Delete_NotFound(t *testing.T) {
	// TODO: Test DELETE non-existent service
	// 1. DELETE with invalid service ID
	// 2. Verify 404 Not Found
}

func TestServiceResource_Delete_Unauthorized(t *testing.T) {
	// TODO: Test DELETE without proper scope
	// 1. Create service with user A
	// 2. Attempt DELETE with user B's token
	// 3. Verify 403 Forbidden
}

func TestServiceResource_MalformedURL(t *testing.T) {
	// TODO: Test service resource with malformed URL
	// 1. GET/DELETE with malformed service URL
	// 2. Verify 400 Bad Request
}
