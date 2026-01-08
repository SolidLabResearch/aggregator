package config

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

	expiry, err := fetchAccessTokenExpiry("test-ns")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if expiry != "2025-01-01T00:00:00Z" {
		t.Fatalf("expected token expiry, got %q", expiry)
	}
}

func TestHandleAggregatorDescription(t *testing.T) {
	origClientset := model.Clientset
	origProtocol := model.Protocol
	origExternalHost := model.ExternalHost
	t.Cleanup(func() {
		model.Clientset = origClientset
		model.Protocol = origProtocol
		model.ExternalHost = origExternalHost
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

	model.Protocol = "http"
	model.ExternalHost = "aggregator.test"

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	recorder := httptest.NewRecorder()
	handleAggregatorDescription(recorder, req, model.User{Namespace: "test-ns"})

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
	if desc.TransformationCatalog != "http://aggregator.test/config/test-ns/transformations" {
		t.Fatalf("unexpected transformation_catalog: %s", desc.TransformationCatalog)
	}
	if desc.ServiceCollection != "http://aggregator.test/config/test-ns/actors" {
		t.Fatalf("unexpected service_collection: %s", desc.ServiceCollection)
	}
	if !desc.LoginStatus {
		t.Fatal("expected login_status true")
	}
	if desc.TokenExpiry != tokenExpiry {
		t.Fatalf("expected token_expiry %s, got %s", tokenExpiry, desc.TokenExpiry)
	}
	if _, err := time.Parse(time.RFC3339, desc.CreatedAt); err != nil {
		t.Fatalf("created_at not RFC3339: %v", err)
	}
}

func TestHandleAggregatorDescription_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	recorder := httptest.NewRecorder()
	handleAggregatorDescription(recorder, req, model.User{Namespace: "test-ns"})

	resp := recorder.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestHandleAggregatorDescription_NotFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/other", nil)
	recorder := httptest.NewRecorder()
	handleAggregatorDescription(recorder, req, model.User{Namespace: "test-ns"})

	resp := recorder.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}
