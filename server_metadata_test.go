package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServerDescription(t *testing.T) {
	mux := http.NewServeMux()
	RegisterServerMetadataEndpoints(mux)

	request := httptest.NewRequest(http.MethodGet, "http://aggregator.example/", nil)
	response := httptest.NewRecorder()

	mux.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, response.Code)
	}
	if contentType := response.Header().Get("Content-Type"); contentType != "application/json" {
		t.Fatalf("expected application/json content type, got %q", contentType)
	}
	if allowOrigin := response.Header().Get("Access-Control-Allow-Origin"); allowOrigin != "*" {
		t.Fatalf("expected permissive CORS header, got %q", allowOrigin)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body is not JSON: %v", err)
	}

	expected := map[string]string{
		"@id":                    "http://aggregator.example/",
		"@type":                  "aggr:AggregatorServer",
		"management_endpoint":    "http://aggregator.example/registration",
		"version":                AggregatorSpecVersion,
		"client_identifier":      "http://aggregator.example/client.jsonld",
		"transformation_catalog": "http://aggregator.example/transformations",
	}
	for key, value := range expected {
		if body[key] != value {
			t.Fatalf("expected %s to be %q, got %#v", key, value, body[key])
		}
	}

	flows, ok := body["supported_management_flows"].([]interface{})
	if !ok || len(flows) != 2 || flows[0] != "none" || flows[1] != "authorization_code" {
		t.Fatalf("expected supported_management_flows to contain none and authorization_code, got %#v", body["supported_management_flows"])
	}
	formats, ok := body["supported_management_request_formats"].([]interface{})
	if !ok || len(formats) != 1 || formats[0] != "application/json" {
		t.Fatalf("expected JSON management request format, got %#v", body["supported_management_request_formats"])
	}
}

func TestClientIDDocument(t *testing.T) {
	mux := http.NewServeMux()
	RegisterServerMetadataEndpoints(mux)

	request := httptest.NewRequest(http.MethodGet, "https://aggregator.example/client.jsonld", nil)
	response := httptest.NewRecorder()

	mux.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, response.Code)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body is not JSON: %v", err)
	}
	if body["client_id"] != "https://aggregator.example/client.jsonld" {
		t.Fatalf("unexpected client_id: %#v", body["client_id"])
	}
	if body["jwks_uri"] != "https://aggregator.example/.well-known/jwks.json" {
		t.Fatalf("unexpected jwks_uri: %#v", body["jwks_uri"])
	}
}

func TestTransformationCatalog(t *testing.T) {
	mux := http.NewServeMux()
	RegisterServerMetadataEndpoints(mux)

	request := httptest.NewRequest(http.MethodGet, "http://aggregator.example/transformations", nil)
	response := httptest.NewRecorder()

	mux.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, response.Code)
	}
	if contentType := response.Header().Get("Content-Type"); contentType != "text/turtle" {
		t.Fatalf("expected text/turtle content type, got %q", contentType)
	}

	body := response.Body.String()
	requiredSnippets := []string{
		"<> a aggr:TransformationCatalog",
		"aggr:hasTransformation <SPARQLEvaluation>",
		"<SPARQLEvaluation>",
		"a                   fno:Function",
		"fno:expects         ( <QueryString> <Sources> )",
		"fno:returns         ( <Result> )",
		"<QueryString>",
		"a             fno:Parameter",
		"<Sources>",
		"<Result>",
		"a             fno:Output",
		"fno:type      dcat:Dataset",
		"fno:predicate <result>",
	}
	for _, snippet := range requiredSnippets {
		if !strings.Contains(body, snippet) {
			t.Fatalf("catalog is missing %q", snippet)
		}
	}
}
