package config

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"aggregator/model"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestFetchAccessTokenExpiry(t *testing.T) {
	origClientset := model.Clientset
	t.Cleanup(func() {
		model.Clientset = origClientset
	})

	model.Clientset = fake.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "aggregator-instance-config",
			Namespace: "test-ns",
		},
		Data: map[string]string{
			"access_token_expiry": "2025-01-01T00:00:00Z",
		},
	})
}

func TestHandleAggregatorDescription(t *testing.T) {
	origClientset := model.Clientset
	origHTTPClient := model.HttpClient
	origProtocol := model.Protocol
	origExternalHost := model.ExternalHost
	origExternalHTTPPort := model.ExternalHttpPort
	origID := model.ID
	origNamespace := model.Namespace
	origDeploymentCatalog := model.DeploymentCatalog
	origServiceCollection := model.ServiceCollection
	t.Cleanup(func() {
		model.Clientset = origClientset
		model.HttpClient = origHTTPClient
		model.Protocol = origProtocol
		model.ExternalHost = origExternalHost
		model.ExternalHttpPort = origExternalHTTPPort
		model.ID = origID
		model.Namespace = origNamespace
		model.DeploymentCatalog = origDeploymentCatalog
		model.ServiceCollection = origServiceCollection
	})

	tokenExpiry := time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339)
	model.Clientset = fake.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "aggregator-instance-config",
			Namespace: "test-ns",
		},
		Data: map[string]string{
			"access_token_expiry": tokenExpiry,
		},
	})
	model.HttpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"login_status":true,"token_expiry":"` + tokenExpiry + `"}`)),
			Request:    request,
		}, nil
	})}

	model.Protocol = "http"
	model.ExternalHost = "aggregator.test"
	model.ExternalHttpPort = "80"
	model.ID = "config/test-ns"
	model.Namespace = "test-ns"
	model.DeploymentCatalog = "/deployments"
	model.ServiceCollection = "/services"

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	recorder := httptest.NewRecorder()
	handleAggregatorDescription(recorder, req)

	resp := recorder.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}

	var desc AggregatorDescription
	if err := json.NewDecoder(resp.Body).Decode(&desc); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if desc.ID != "http://aggregator.test/config/test-ns" {
		t.Fatalf("unexpected id: %s", desc.ID)
	}
	if desc.DeploymentCatalog != "http://aggregator.test/deployments" {
		t.Fatalf("unexpected deployment_catalog: %s", desc.DeploymentCatalog)
	}
	if desc.ServiceCollection != "http://aggregator.test/config/test-ns/services" {
		t.Fatalf("unexpected service_collection: %s", desc.ServiceCollection)
	}
	if !desc.LoginStatus {
		t.Fatal("expected login_status true")
	}
	if _, err := time.Parse(time.RFC3339, desc.CreatedAt); err != nil {
		t.Fatalf("created_at not RFC3339: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestHandleAggregatorDescription_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	recorder := httptest.NewRecorder()
	handleAggregatorDescription(recorder, req)

	resp := recorder.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestHandleAggregatorDescription_NotFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/other", nil)
	recorder := httptest.NewRecorder()
	handleAggregatorDescription(recorder, req)

	resp := recorder.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}
