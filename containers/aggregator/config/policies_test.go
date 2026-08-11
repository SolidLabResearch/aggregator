package config

import (
	"aggregator/model"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPoliciesPostRequiresJSONLD(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/policies", strings.NewReader(`{}`))
	response := httptest.NewRecorder()
	handlePolicies(response, request)
	if response.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnsupportedMediaType)
	}
}

func TestPoliciesPostCreatesDefaultPolicy(t *testing.T) {
	originalID, originalNamespace := model.ID, model.Namespace
	originalOwner, originalProvisionID := model.Owner, model.ProvisionID
	originalClient := model.HttpClient
	model.ID = "agg-1"
	model.Namespace = "aggregator-app"
	model.Owner = model.User{UserId: "owner", AuthzServerURL: "https://uma.example"}
	model.ProvisionID = "provisioner"
	model.HttpClient = &http.Client{Transport: policyRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/default-policies") {
			return &http.Response{
				StatusCode: http.StatusCreated,
				Body: io.NopCloser(strings.NewReader(
					`{"id":"policy-1","policy":{"@context":"http://www.w3.org/ns/odrl.jsonld","@type":"Offer","uid":"urn:policy:1","permission":[{"@type":"Permission"}]}}`,
				)),
				Header: http.Header{},
			}, nil
		}
		if request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/resources") {
			return &http.Response{StatusCode: http.StatusCreated, Body: io.NopCloser(strings.NewReader(`{}`)), Header: http.Header{}}, nil
		}
		t.Fatalf("unexpected internal request: %s %s", request.Method, request.URL)
		return nil, nil
	})}
	t.Cleanup(func() {
		model.ID, model.Namespace = originalID, originalNamespace
		model.Owner, model.ProvisionID = originalOwner, originalProvisionID
		model.HttpClient = originalClient
	})

	request := httptest.NewRequest(http.MethodPost, "/policies", strings.NewReader(
		`{"@context":"http://www.w3.org/ns/odrl.jsonld","@type":"Offer","uid":"urn:policy:1","permission":[{"@type":"Permission"}]}`,
	))
	request.Header.Set("Content-Type", "application/ld+json")
	response := httptest.NewRecorder()
	handlePolicies(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if location := response.Header().Get("Location"); !strings.HasSuffix(location, "/policies/policy-1") {
		t.Fatalf("unexpected Location %q", location)
	}
}

type policyRoundTripFunc func(*http.Request) (*http.Response, error)

func (function policyRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
