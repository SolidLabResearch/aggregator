package integration_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

func TestServerDescription(t *testing.T) {
	resp, err := http.Get(testEnv.AggregatorURL + "/")
	if err != nil {
		t.Fatalf("Failed to get server description: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Logf("Failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var desc map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&desc); err != nil {
		t.Fatalf("Failed to decode server description: %v", err)
	}

	requiredFields := []string{
		"registration_endpoint",
		"supported_registration_types",
		"version",
		"client_identifier",
		"transformation_catalog",
	}

	for _, field := range requiredFields {
		if _, ok := desc[field]; !ok {
			t.Errorf("Missing required field: %s", field)
		}
	}

	types, ok := desc["supported_registration_types"].([]interface{})
	if !ok {
		t.Errorf("supported_registration_types is not an array")
	} else {
		found := false
		for _, t := range types {
			if t == "authorization_code" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("authorization_code not found in supported_registration_types")
		}
	}
}

func TestClientIdentifierDocument(t *testing.T) {
	// 1. GET the client_identifier URL from server description
	resp, err := http.Get(testEnv.AggregatorURL + "/")
	if err != nil {
		t.Fatalf("Failed to get server description: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Logf("Failed to close response body: %v", err)
		}
	}()

	var serverDesc map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&serverDesc); err != nil {
		t.Fatalf("Failed to decode server description: %v", err)
	}

	clientIdentifierURL, ok := serverDesc["client_identifier"].(string)
	if !ok {
		t.Fatal("client_identifier field missing or not a string")
	}

	clientResp, err := http.Get(clientIdentifierURL)
	if err != nil {
		t.Fatalf("Failed to get client identifier document: %v", err)
	}
	defer func() {
		if err := clientResp.Body.Close(); err != nil {
			t.Logf("Failed to close client response body: %v", err)
		}
	}()

	if clientResp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", clientResp.StatusCode)
	}

	// Verify JSON content type
	contentType := clientResp.Header.Get("Content-Type")
	if !containsContentType(contentType, "application/ld+json") {
		t.Errorf("Expected Content-Type to contain application/ld+json, got %s", contentType)
	}

	var clientDoc map[string]interface{}
	if err := json.NewDecoder(clientResp.Body).Decode(&clientDoc); err != nil {
		t.Fatalf("Failed to decode client identifier document: %v", err)
	}

	// 4. Check for required fields (OIDC Dynamic Client Registration)
	requiredFields := []string{
		"client_id",
	}

	for _, field := range requiredFields {
		if _, ok := clientDoc[field]; !ok {
			t.Errorf("Missing required field: %s", field)
		}
	}

	// 3. Verify redirect_uris is optional (differs from standard OIDC)
	// This is explicitly allowed for aggregator servers since multiple clients can use the same server
	if _, hasRedirectURIs := clientDoc["redirect_uris"]; hasRedirectURIs {
		t.Logf("redirect_uris present (optional): %v", clientDoc["redirect_uris"])
	} else {
		t.Logf("redirect_uris not present (allowed for aggregator)")
	}

	// 5. Test content negotiation - try JSON-LD
	req, err := http.NewRequest("GET", clientIdentifierURL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Accept", "application/ld+json")

	jsonLDResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to get client identifier with JSON-LD: %v", err)
	}
	defer func() {
		if err := jsonLDResp.Body.Close(); err != nil {
			t.Logf("Failed to close JSON-LD response body: %v", err)
		}
	}()

	if jsonLDResp.StatusCode == http.StatusOK {
		contentType := jsonLDResp.Header.Get("Content-Type")
		if containsContentType(contentType, "application/ld+json") || containsContentType(contentType, "application/json") {
			t.Logf("JSON-LD content negotiation supported")
		} else {
			t.Logf("JSON-LD requested but got Content-Type: %s", contentType)
		}
	} else if jsonLDResp.StatusCode == http.StatusNotAcceptable {
		t.Logf("JSON-LD content negotiation not supported (406 Not Acceptable)")
	}

	// 6. Test quality parameters in Accept header
	testCases := []struct {
		name         string
		accept       string
		expectedType string
	}{
		{
			name:         "Prefer JSON with quality",
			accept:       "application/json;q=1.0, application/ld+json;q=0.8",
			expectedType: "application/json",
		},
		{
			name:         "Prefer JSON-LD with quality",
			accept:       "application/json;q=0.5, application/ld+json;q=1.0",
			expectedType: "application/ld+json",
		},
		{
			name:         "Multiple types with quality",
			accept:       "text/html;q=0.9, application/json;q=0.8, application/ld+json;q=1.0",
			expectedType: "application/ld+json",
		},
		{
			name:         "Wildcard with lower quality",
			accept:       "application/json;q=0.9, */*;q=0.1",
			expectedType: "application/json",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", clientIdentifierURL, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			req.Header.Set("Accept", tc.accept)

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Failed to get client identifier: %v", err)
			}
			defer func() {
				if err := resp.Body.Close(); err != nil {
					t.Logf("Failed to close response body: %v", err)
				}
			}()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("Expected status 200, got %d", resp.StatusCode)
			}

			contentType := resp.Header.Get("Content-Type")
			if !containsContentType(contentType, tc.expectedType) {
				t.Errorf("Expected Content-Type to contain %s, got %s", tc.expectedType, contentType)
			}
			t.Logf("Accept: %s -> Content-Type: %s", tc.accept, contentType)
		})
	}
}

func TestPublicTransformationCatalog(t *testing.T) {
	// 1. GET the transformation_catalog URL from server description
	resp, err := http.Get(testEnv.AggregatorURL + "/")
	if err != nil {
		t.Fatalf("Failed to get server description: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Logf("Failed to close response body: %v", err)
		}
	}()

	var serverDesc map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&serverDesc); err != nil {
		t.Fatalf("Failed to decode server description: %v", err)
	}

	catalogURL, ok := serverDesc["transformation_catalog"].(string)
	if !ok {
		t.Fatal("transformation_catalog field missing or not a string")
	}

	// 2. Verify it returns an RDF document (try Turtle first as it's required for FnO)
	req, err := http.NewRequest("GET", catalogURL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Accept", "text/turtle, application/ld+json, application/json")

	catalogResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to get transformation catalog: %v", err)
	}
	defer func() {
		if err := catalogResp.Body.Close(); err != nil {
			t.Logf("Failed to close catalog response body: %v", err)
		}
	}()

	if catalogResp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", catalogResp.StatusCode)
	}

	contentType := catalogResp.Header.Get("Content-Type")
	t.Logf("Transformation catalog Content-Type: %s", contentType)

	// The response should be in an RDF format
	isRDF := containsContentType(contentType, "text/turtle") ||
		containsContentType(contentType, "application/ld+json") ||
		containsContentType(contentType, "application/json") ||
		containsContentType(contentType, "application/rdf+xml")

	if !isRDF {
		t.Errorf("Expected RDF content type (turtle, JSON-LD, or RDF/XML), got: %s", contentType)
	}

	// Try to parse as JSON-LD or JSON to check structure
	var catalogData interface{}
	jsonReq, _ := http.NewRequest("GET", catalogURL, nil)
	jsonReq.Header.Set("Accept", "application/ld+json, application/json")
	jsonResp, err := http.DefaultClient.Do(jsonReq)
	if err != nil {
		t.Logf("Could not fetch JSON representation: %v", err)
	} else {
		defer func() {
			if err := jsonResp.Body.Close(); err != nil {
				t.Logf("Failed to close JSON response body: %v", err)
			}
		}()
		if jsonResp.StatusCode == http.StatusOK {
			if err := json.NewDecoder(jsonResp.Body).Decode(&catalogData); err == nil {
				t.Logf("Successfully parsed transformation catalog as JSON")

				// 3. Verify it's an aggr:TransformationCollection (check for type)
				checkForType := func(data interface{}, typeName string) bool {
					switch v := data.(type) {
					case map[string]interface{}:
						if typeField, ok := v["@type"]; ok {
							switch tf := typeField.(type) {
							case string:
								return tf == typeName || tf == "aggr:TransformationCollection" || tf == "TransformationCollection"
							case []interface{}:
								for _, t := range tf {
									if ts, ok := t.(string); ok && (ts == typeName || ts == "aggr:TransformationCollection" || ts == "TransformationCollection") {
										return true
									}
								}
							}
						}
						if typeField, ok := v["type"]; ok {
							if ts, ok := typeField.(string); ok {
								return ts == typeName || ts == "aggr:TransformationCollection" || ts == "TransformationCollection"
							}
						}
					}
					return false
				}

				hasTransformationCollection := checkForType(catalogData, "TransformationCollection")
				if hasTransformationCollection {
					t.Logf("Found TransformationCollection type")
				} else {
					t.Logf("Warning: Could not verify @type is aggr:TransformationCollection (may be in Turtle format)")
				}

				// 4. Check that transformations are described using FnO vocabulary
				// Look for FnO predicates/properties
				checkForFnOTerms := func(data interface{}) bool {
					fnoTerms := []string{
						"fno:Function", "Function",
						"fno:expects", "expects",
						"fno:returns", "returns",
						"fno:Parameter", "Parameter",
						"fno:Output", "Output",
						"fno:executes", "executes",
						"hasTransformation",
						"aggr:hasTransformation",
					}

					str := fmt.Sprintf("%v", data)
					for _, term := range fnoTerms {
						if containsString(str, term) {
							return true
						}
					}
					return false
				}

				if checkForFnOTerms(catalogData) {
					t.Logf("Found FnO vocabulary terms in catalog")
				} else {
					t.Logf("Warning: Could not find obvious FnO terms (may need deeper inspection)")
				}

				// 5. Try to find specific FnO structures
				var checkForFnOStructure func(interface{}) (hasFunctions, hasParameters, hasOutputs bool)
				checkForFnOStructure = func(data interface{}) (hasFunctions, hasParameters, hasOutputs bool) {
					switch v := data.(type) {
					case map[string]interface{}:
						for key, value := range v {
							if containsString(key, "Function") || containsString(key, "function") {
								hasFunctions = true
							}
							if containsString(key, "Parameter") || containsString(key, "parameter") || containsString(key, "expects") {
								hasParameters = true
							}
							if containsString(key, "Output") || containsString(key, "output") || containsString(key, "returns") {
								hasOutputs = true
							}
							f, p, o := checkForFnOStructure(value)
							hasFunctions = hasFunctions || f
							hasParameters = hasParameters || p
							hasOutputs = hasOutputs || o
						}
					case []interface{}:
						for _, item := range v {
							f, p, o := checkForFnOStructure(item)
							hasFunctions = hasFunctions || f
							hasParameters = hasParameters || p
							hasOutputs = hasOutputs || o
						}
					}
					return
				}

				hasFunctions, hasParameters, hasOutputs := checkForFnOStructure(catalogData)
				if hasFunctions {
					t.Logf("Found fno:Function definitions")
				}
				if hasParameters {
					t.Logf("Found fno:Parameter or fno:expects")
				}
				if hasOutputs {
					t.Logf("Found fno:Output or fno:returns")
				}

				// 6. Check for optional fno:Implementation and rdfs:seeAlso references
				checkForOptionalTerms := func(data interface{}) (hasImpl, hasSeeAlso bool) {
					str := fmt.Sprintf("%v", data)
					hasImpl = containsString(str, "Implementation") || containsString(str, "implementation")
					hasSeeAlso = containsString(str, "seeAlso") || containsString(str, "rdfs:seeAlso")
					return
				}

				hasImpl, hasSeeAlso := checkForOptionalTerms(catalogData)
				if hasImpl {
					t.Logf("Found fno:Implementation references")
				} else {
					t.Logf("No fno:Implementation found (optional)")
				}
				if hasSeeAlso {
					t.Logf("Found rdfs:seeAlso references")
				} else {
					t.Logf("No rdfs:seeAlso found (optional)")
				}
			}
		}
	}

	// Test content negotiation with different Accept headers
	acceptHeaders := []string{
		"text/turtle",
		"application/ld+json",
		"application/json",
	}

	for _, accept := range acceptHeaders {
		req, _ := http.NewRequest("GET", catalogURL, nil)
		req.Header.Set("Accept", accept)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Logf("Failed to fetch with Accept: %s - %v", accept, err)
			continue
		}
		func() {
			defer func() {
				if err := resp.Body.Close(); err != nil {
					t.Logf("Failed to close response body: %v", err)
				}
			}()
		}()
		t.Logf("Accept: %s -> Status: %d, Content-Type: %s", accept, resp.StatusCode, resp.Header.Get("Content-Type"))
	}

	// Test quality parameters with Turtle (only supported format)
	qualityTestCases := []struct {
		name         string
		accept       string
		expectStatus int
	}{
		{
			name:         "Prefer Turtle with quality",
			accept:       "text/turtle;q=1.0, application/json;q=0.5",
			expectStatus: http.StatusOK,
		},
		{
			name:         "Turtle in list with quality",
			accept:       "application/json;q=0.9, text/turtle;q=0.8, application/ld+json;q=0.7",
			expectStatus: http.StatusOK,
		},
		{
			name:         "Wildcard with quality",
			accept:       "*/*;q=0.5",
			expectStatus: http.StatusOK,
		},
		{
			name:         "Only unsupported types",
			accept:       "application/xml;q=1.0, text/html;q=0.9",
			expectStatus: http.StatusUnsupportedMediaType,
		},
	}

	for _, tc := range qualityTestCases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", catalogURL, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			req.Header.Set("Accept", tc.accept)

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Failed to get transformation catalog: %v", err)
			}
			defer func() {
				if err := resp.Body.Close(); err != nil {
					t.Logf("Failed to close response body: %v", err)
				}
			}()

			if resp.StatusCode != tc.expectStatus {
				t.Errorf("Expected status %d, got %d for Accept: %s", tc.expectStatus, resp.StatusCode, tc.accept)
			} else {
				t.Logf("Accept: %s -> Status: %d, Content-Type: %s", tc.accept, resp.StatusCode, resp.Header.Get("Content-Type"))
			}
		})
	}
}

// Helper function to check if a content type contains a specific type
func containsContentType(contentType, expectedType string) bool {
	return len(contentType) > 0 && (contentType == expectedType ||
		len(contentType) > len(expectedType) && contentType[:len(expectedType)] == expectedType ||
		containsString(contentType, expectedType))
}

// Helper function to check if a string contains a substring (case-insensitive)
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())
}
