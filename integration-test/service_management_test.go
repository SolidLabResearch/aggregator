package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"aggregator-integration-test/mocks"
	corev1 "k8s.io/api/core/v1"
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

	collection := decodeServiceCollection(t, bodyBytes)
	if len(collection.Services) != 0 {
		t.Fatalf("Expected empty service collection, got %d items", len(collection.Services))
	}
}

func TestServiceCollection_Get_WithServices(t *testing.T) {
	instance := setupAggregatorInstance(t)
	defer instance.cleanup()

	desc := fetchAggregatorDescription(t, instance.baseURL, instance.authToken)

	service := createService(t, desc.ServiceCollection, instance.authToken)

	resp, bodyBytes := getWithUMA(t, desc.ServiceCollection, instance.authToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d: %s", resp.StatusCode, string(bodyBytes))
	}

	collection := decodeServiceCollection(t, bodyBytes)
	if len(collection.Services) == 0 {
		t.Fatal("Expected service collection to contain entries")
	}

	// Check if service.ID is in collection.Services
	found := false
	for _, s := range collection.Services {
		if s == service.ID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Expected service %s to appear in collection", service.ID)
	}
}

func TestServiceCollection_ETagChanges(t *testing.T) {
	instance := setupAggregatorInstance(t)
	defer instance.cleanup()

	desc := fetchAggregatorDescription(t, instance.baseURL, instance.authToken)

	etagBefore := getCollectionETag(t, desc.ServiceCollection, instance.authToken)

	service := createService(t, desc.ServiceCollection, instance.authToken)
	if service.ID == "" {
		t.Fatal("Created service missing id")
	}

	etagAfterCreate := getCollectionETag(t, desc.ServiceCollection, instance.authToken)
	if etagAfterCreate == etagBefore {
		t.Fatalf("Expected ETag to change after create (still %q)", etagAfterCreate)
	}

	deleteService(t, service.ID, instance.authToken)

	etagAfterDelete := getCollectionETag(t, desc.ServiceCollection, instance.authToken)
	if etagAfterDelete == etagAfterCreate {
		t.Fatalf("Expected ETag to change after delete (still %q)", etagAfterDelete)
	}
}

func TestServiceCollection_Post_CreateSimpleService(t *testing.T) {
	instance := setupAggregatorInstance(t)
	defer instance.cleanup()

	desc := fetchAggregatorDescription(t, instance.baseURL, instance.authToken)

	service := createService(t, desc.ServiceCollection, instance.authToken)
	assertServiceRepresentation(t, service)
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
	instance := setupAggregatorInstance(t)
	defer instance.cleanup()

	desc := fetchAggregatorDescription(t, instance.baseURL, instance.authToken)

	// Invalid Turtle - parsing will fail during service creation, resulting in 500
	resp, bodyBytes := doWithUMA(t, http.MethodPost, desc.ServiceCollection, instance.authToken, []byte(`invalid turtle`), "text/turtle")
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("Expected 500 Internal Server Error for invalid body, got %d: %s", resp.StatusCode, string(bodyBytes))
	}
}

func TestServiceCollection_Post_ServiceInstantiationFailure(t *testing.T) {
	// TODO: Test POST when service cannot be instantiated
	// 1. Create valid FnO execution
	// 2. Mock upstream resources to be unavailable
	// 3. Verify 500 Internal Server Error
}

func TestServiceCollection_Post_ExecutionUsesQueryAndSources(t *testing.T) {
	instance := setupAggregatorInstance(t)
	defer instance.cleanup()

	desc := fetchAggregatorDescription(t, instance.baseURL, instance.authToken)

	query := "SELECT * WHERE { ?s ?p ?o }"
	source := "http://example.com"
	
	// Build FnO Turtle description
	serverDesc := fetchAggregatorServerDescription(t)
	transformationsCatalog := serverDesc["transformation_catalog"].(string)
	
	turtleBody := fmt.Sprintf(`@prefix config: <%s> .
@prefix fno: <https://w3id.org/function/ontology#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .

_:execution a fno:Execution ;
    fno:executes config:SPARQLEvaluation ;
    config:sources ( "%s"^^xsd:string ) ;
    config:queryString "%s" .`, transformationsCatalog, source, query)

	resp, bodyBytes := doWithUMA(t, http.MethodPost, desc.ServiceCollection, instance.authToken, []byte(turtleBody), "text/turtle")
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusCreated {
		t.Fatalf("Expected 201/202 for execution creation, got %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var service serviceRepresentation
	if err := json.Unmarshal(bodyBytes, &service); err != nil {
		t.Fatalf("Failed to decode service response: %v", err)
	}
	if service.ID == "" {
		t.Fatal("Service response missing id")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// Extract service ID from URL for deployment lookup
	parts := strings.Split(service.ID, "/")
	shortID := parts[len(parts)-1]
	deployment := waitForDeploymentExists(t, ctx, instance.namespace, shortID)

	assertEnvValue(t, deployment.Spec.Template.Spec.Containers[0].Env, "QUERY", query)
	assertEnvValue(t, deployment.Spec.Template.Spec.Containers[0].Env, "SOURCE", source)
}

func TestServiceCreation_UMAProtectsServiceEndpoints(t *testing.T) {
	instance := setupAggregatorInstance(t)
	defer instance.cleanup()

	desc := fetchAggregatorDescription(t, instance.baseURL, instance.authToken)

	service := createService(t, desc.ServiceCollection, instance.authToken)
	if service.Location == "" {
		t.Fatal("Service response missing location")
	}

	// Wait for service to be ready using service ID
	waitForServiceReady(t, service.ID, instance.authToken, 60*time.Second)

	// Check access to Location without auth
	resp, err := http.Get(service.Location)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if resp != nil {
		resp.Body.Close()
	}
	if resp == nil || (resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden) {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("Expected 401/403 for unauthenticated service location, got %d", status)
	}

	// Check access to Location with auth
	resp, bodyBytes := getWithUMA(t, service.Location, instance.authToken)
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		t.Fatalf("Expected authenticated service location access, got %d: %s", resp.StatusCode, string(bodyBytes))
	}
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
	instance := setupAggregatorInstance(t)
	defer instance.cleanup()

	desc := fetchAggregatorDescription(t, instance.baseURL, instance.authToken)
	service := createService(t, desc.ServiceCollection, instance.authToken)

	resp, bodyBytes := doWithUMA(t, http.MethodHead, service.ID, instance.authToken, nil, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d: %s", resp.StatusCode, string(bodyBytes))
	}
	if resp.Header.Get("ETag") == "" {
		t.Fatal("Expected ETag header for service resource")
	}
	contentType := resp.Header.Get("Content-Type")
	if !containsContentType(contentType, "application/json") {
		t.Fatalf("Expected application/json content-type, got %s", contentType)
	}
	if len(bodyBytes) != 0 {
		t.Fatalf("Expected empty body for HEAD, got %q", string(bodyBytes))
	}
}

func TestServiceResource_Get(t *testing.T) {
	instance := setupAggregatorInstance(t)
	defer instance.cleanup()

	desc := fetchAggregatorDescription(t, instance.baseURL, instance.authToken)
	service := createService(t, desc.ServiceCollection, instance.authToken)

	resp, bodyBytes := getWithUMA(t, service.ID, instance.authToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d: %s", resp.StatusCode, string(bodyBytes))
	}

	contentType := resp.Header.Get("Content-Type")
	if !containsContentType(contentType, "application/json") {
		t.Fatalf("Expected application/json content-type, got %s", contentType)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		t.Fatalf("Failed to decode service resource: %v", err)
	}

	for _, field := range []string{"id", "status", "transformation", "created_at", "location"} {
		if _, ok := payload[field]; !ok {
			t.Fatalf("Service resource missing required field %q", field)
		}
	}
}

func TestServiceResource_Get_StatusValues(t *testing.T) {
	// TODO: Test different service status values
	// 1. Create service and verify status: "running"
	// 2. Trigger service restart, verify status: "restarting"
	// 3. Stop service, verify status: "stopped"
	// 4. Cause error condition, verify status: "errored"
}

func TestServiceResource_Delete(t *testing.T) {
	instance := setupAggregatorInstance(t)
	defer instance.cleanup()

	desc := fetchAggregatorDescription(t, instance.baseURL, instance.authToken)

	service := createService(t, desc.ServiceCollection, instance.authToken)
	etagBefore := getCollectionETag(t, desc.ServiceCollection, instance.authToken)

	deleteService(t, service.ID, instance.authToken)

	resp, bodyBytes := getWithUMA(t, service.ID, instance.authToken)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Expected 404 after delete, got %d: %s", resp.StatusCode, string(bodyBytes))
	}

	etagAfter := getCollectionETag(t, desc.ServiceCollection, instance.authToken)
	if etagAfter == etagBefore {
		t.Fatalf("Expected collection ETag to change after delete (still %q)", etagAfter)
	}
}

func TestServiceResource_Delete_NotFound(t *testing.T) {
	instance := setupAggregatorInstance(t)
	defer instance.cleanup()

	desc := fetchAggregatorDescription(t, instance.baseURL, instance.authToken)

	resp, bodyBytes := doWithUMA(t, http.MethodDelete, desc.ServiceCollection+"/non-existent", instance.authToken, nil, "")
	if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Expected 404 or 401, got %d: %s", resp.StatusCode, string(bodyBytes))
	}
}

func TestServiceResource_Delete_Unauthorized(t *testing.T) {
	t.Skip("TODO: UMA authorization for DELETE operations needs to be properly enforced")
	instance := setupAggregatorInstance(t)
	defer instance.cleanup()

	desc := fetchAggregatorDescription(t, instance.baseURL, instance.authToken)
	service := createService(t, desc.ServiceCollection, instance.authToken)

	// Wait for service to be ready
	waitForServiceReady(t, service.ID, instance.authToken, 60*time.Second)

	otherProvider, err := mocks.NewOIDCProvider()
	if err != nil {
		t.Fatalf("Failed to create other OIDC provider: %v", err)
	}
	defer otherProvider.Close()
	otherWebID := otherProvider.URL() + "/webid#me"
	otherToken := createAuthToken(t, otherProvider, otherWebID)

	// Try to delete with different user's token
	resp, bodyBytes := doWithUMA(t, http.MethodDelete, service.ID, otherToken, nil, "")
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Expected 401/403 for unauthorized delete, got %d: %s", resp.StatusCode, string(bodyBytes))
	}
	
	// Verify service still exists after failed delete
	getResp, _ := getWithUMA(t, service.ID, instance.authToken)
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("Service should still exist after unauthorized delete attempt, got %d", getResp.StatusCode)
	}
}

func TestServiceResource_MalformedURL(t *testing.T) {
	instance := setupAggregatorInstance(t)
	defer instance.cleanup()

	desc := fetchAggregatorDescription(t, instance.baseURL, instance.authToken)

	resp, bodyBytes := getWithUMA(t, desc.ServiceCollection+"/", instance.authToken)
	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Expected 400 Bad Request or 401, got %d: %s", resp.StatusCode, string(bodyBytes))
	}
}

type serviceCollection struct {
	ID       string
	Services []string
}

type serviceRepresentation struct {
	ID            string      `json:"id"`
	Status        string      `json:"status"`
	CreatedAt     string      `json:"created_at"`
	Location      string      `json:"location"`
	Transformation interface{} `json:"transformation"`
}

func decodeServiceCollection(t *testing.T, body []byte) serviceCollection {
	t.Helper()

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("Failed to decode service collection: %v", err)
	}

	collection := serviceCollection{}
	if rawID, ok := payload["id"].(string); ok {
		collection.ID = rawID
	}

	rawServices, ok := payload["services"]
	if !ok {
		t.Fatal("Service collection missing services array")
	}
	servicesSlice, ok := rawServices.([]interface{})
	if !ok {
		t.Fatalf("services is not an array: %T", rawServices)
	}
	for _, entry := range servicesSlice {
		value, ok := entry.(string)
		if !ok {
			t.Fatalf("service entry is not a string: %T", entry)
		}
		collection.Services = append(collection.Services, value)
	}

	return collection
}


func waitForServiceReady(t *testing.T, serviceURL string, authToken string, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, bodyBytes := getWithUMA(t, serviceURL, authToken)
		if resp.StatusCode == http.StatusOK {
			var payload map[string]interface{}
			if err := json.Unmarshal(bodyBytes, &payload); err != nil {
				t.Fatalf("Failed to decode service status response: %v", err)
			}
			if status, ok := payload["status"].(string); ok && status == "running" {
				return
			}
		}
		if resp.StatusCode != http.StatusServiceUnavailable && resp.StatusCode != http.StatusOK {
			t.Fatalf("Unexpected status response %d: %s", resp.StatusCode, string(bodyBytes))
		}
		time.Sleep(2 * time.Second)
	}

	t.Fatalf("Timed out waiting for service readiness at %s", serviceURL)
}

func buildFnOExecution(query string, source string) string {
	return fmt.Sprintf(`@base <http://aggregator.local/config/transformations#> .
@prefix fno: <https://w3id.org/function/ontology#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
<> a fno:Execution ;
    fno:executes <SPARQLEvaluation> ;
    <queryString> "%s"^^xsd:string ;
    <sources> ( "%s"^^xsd:string ) .
`, query, source)
}

func assertEnvValue(t *testing.T, envs []corev1.EnvVar, name string, expected string) {
	t.Helper()

	for _, env := range envs {
		if env.Name == name {
			if env.Value != expected {
				t.Fatalf("Expected env %s to be %q, got %q", name, expected, env.Value)
			}
			return
		}
	}
	t.Fatalf("Expected env %s to be set", name)
}

func createService(t *testing.T, collectionURL string, authToken string) serviceRepresentation {
	t.Helper()

	// Build FnO Turtle description
	source := "http://example.org/source"
	query := "SELECT * WHERE { ?s ?p ?o }"
	
	// Extract transformation catalog from aggregator server
	serverDesc := fetchAggregatorServerDescription(t)
	transformationsCatalog := serverDesc["transformation_catalog"].(string)
	
	turtleBody := fmt.Sprintf(`@prefix config: <%s> .
@prefix fno: <https://w3id.org/function/ontology#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .

_:execution a fno:Execution ;
    fno:executes config:SPARQLEvaluation ;
    config:sources ( "%s"^^xsd:string ) ;
    config:queryString "%s" .`, transformationsCatalog, source, query)

	resp, bodyBytes := doWithUMA(t, http.MethodPost, collectionURL, authToken, []byte(turtleBody), "text/turtle")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Expected 201 Created, got %d: %s", resp.StatusCode, string(bodyBytes))
	}

	contentType := resp.Header.Get("Content-Type")
	if !containsContentType(contentType, "application/json") {
		t.Fatalf("Expected application/json content-type, got %s", contentType)
	}

	var service serviceRepresentation
	if err := json.Unmarshal(bodyBytes, &service); err != nil {
		t.Fatalf("Failed to decode service response: %v", err)
	}

	return service
}

func assertServiceRepresentation(t *testing.T, service serviceRepresentation) {
	t.Helper()

	if service.ID == "" {
		t.Fatal("Service missing id")
	}
	if !strings.HasPrefix(service.ID, "http://") && !strings.HasPrefix(service.ID, "https://") {
		t.Fatalf("Service id is not an absolute URL: %s", service.ID)
	}
	if service.Status == "" {
		t.Fatal("Service missing status")
	}
	if service.CreatedAt == "" {
		t.Fatal("Service missing created_at")
	}
	if service.Location == "" {
		t.Fatal("Service missing location")
	}
	if service.Transformation == nil {
		t.Fatal("Service missing transformation")
	}
}

func deleteService(t *testing.T, serviceURL string, authToken string) {
	t.Helper()

	resp, bodyBytes := doWithUMA(t, http.MethodDelete, serviceURL, authToken, nil, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK on delete, got %d: %s", resp.StatusCode, string(bodyBytes))
	}
}

func getCollectionETag(t *testing.T, collectionURL string, authToken string) string {
	t.Helper()

	resp, bodyBytes := doWithUMA(t, http.MethodHead, collectionURL, authToken, nil, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d: %s", resp.StatusCode, string(bodyBytes))
	}
	etag := resp.Header.Get("ETag")
	if etag == "" {
		t.Fatal("Expected ETag header")
	}
	return etag
}
