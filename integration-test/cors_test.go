package integration_test

import (
	"net/http"
	"strings"
	"testing"
)

func TestCORS_Preflight_AllEndpoints(t *testing.T) {
	instance := setupAggregatorInstance(t)
	defer instance.cleanup()

	desc := fetchAggregatorDescription(t, instance.baseURL, instance.authToken)
	service := createService(t, desc.ServiceCollection, instance.authToken)

	endpoints := []struct {
		name    string
		url     string
		methods []string
	}{
		{
			name:    "server-description",
			url:     testEnv.AggregatorURL + "/",
			methods: []string{http.MethodGet},
		},
		{
			name:    "registration",
			url:     testEnv.AggregatorURL + "/registration",
			methods: []string{http.MethodPost, http.MethodDelete},
		},
		{
			name:    "instance-description",
			url:     instance.baseURL,
			methods: []string{http.MethodGet},
		},
		{
			name:    "service-collection",
			url:     desc.ServiceCollection,
			methods: []string{http.MethodHead, http.MethodGet, http.MethodPost},
		},
		{
			name:    "service-resource",
			url:     service.ID,
			methods: []string{http.MethodHead, http.MethodGet, http.MethodDelete},
		},
	}

	for _, endpoint := range endpoints {
		for _, method := range endpoint.methods {
			t.Run(endpoint.name+"-"+method, func(t *testing.T) {
				assertCorsPreflight(t, endpoint.url, method)
			})
		}
	}
}

func assertCorsPreflight(t *testing.T, url string, method string) {
	t.Helper()

	req, err := http.NewRequest(http.MethodOptions, url, nil)
	if err != nil {
		t.Fatalf("Failed to create CORS preflight request: %v", err)
	}

	origin := "https://client.example"
	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", method)
	req.Header.Set("Access-Control-Request-Headers", "Authorization, Content-Type")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("CORS preflight request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200/204 for CORS preflight, got %d", resp.StatusCode)
	}

	allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	if allowOrigin == "" {
		t.Fatal("Expected Access-Control-Allow-Origin header")
	}
	if allowOrigin != "*" && allowOrigin != origin {
		t.Fatalf("Expected Access-Control-Allow-Origin to be '*' or %q, got %q", origin, allowOrigin)
	}

	allowMethods := resp.Header.Get("Access-Control-Allow-Methods")
	if allowMethods == "" {
		t.Fatal("Expected Access-Control-Allow-Methods header")
	}
	if !headerAllowsToken(allowMethods, method) {
		t.Fatalf("Expected Access-Control-Allow-Methods to include %s, got %q", method, allowMethods)
	}

	allowHeaders := resp.Header.Get("Access-Control-Allow-Headers")
	if allowHeaders == "" {
		t.Fatal("Expected Access-Control-Allow-Headers header")
	}
	if !headerAllowsToken(allowHeaders, "Authorization") || !headerAllowsToken(allowHeaders, "Content-Type") {
		t.Fatalf("Expected Access-Control-Allow-Headers to include Authorization and Content-Type, got %q", allowHeaders)
	}
}

func headerAllowsToken(headerValue, token string) bool {
	if headerValue == "*" {
		return true
	}
	for _, part := range strings.Split(headerValue, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}
