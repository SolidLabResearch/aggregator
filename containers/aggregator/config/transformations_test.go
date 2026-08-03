package config

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDeploymentsHead(t *testing.T) {
	config := DeploymentCatalog{
		etag:        7,
		description: "test-deployments",
	}

	req := httptest.NewRequest(http.MethodHead, "/deployments", nil)
	recorder := httptest.NewRecorder()
	config.HandleDeploymentsEndpoint(recorder, req)

	resp := recorder.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
	if resp.Header.Get("ETag") != "7" {
		t.Fatalf("expected ETag 7, got %s", resp.Header.Get("ETag"))
	}
	if resp.Header.Get("Content-Type") != "text/turtle" {
		t.Fatalf("expected text/turtle, got %s", resp.Header.Get("Content-Type"))
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) != 0 {
		t.Fatalf("expected empty body for HEAD, got %q", string(body))
	}
}

func TestDeploymentsGet(t *testing.T) {
	config := DeploymentCatalog{
		etag:        3,
		description: "test-deployments",
	}

	req := httptest.NewRequest(http.MethodGet, "/deployments", nil)
	recorder := httptest.NewRecorder()
	config.HandleDeploymentsEndpoint(recorder, req)

	resp := recorder.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
	if resp.Header.Get("ETag") != "3" {
		t.Fatalf("expected ETag 3, got %s", resp.Header.Get("ETag"))
	}
	if resp.Header.Get("Content-Type") != "text/turtle" {
		t.Fatalf("expected text/turtle, got %s", resp.Header.Get("Content-Type"))
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "test-deployments" {
		t.Fatalf("unexpected body: %q", string(body))
	}
}

func TestDeploymentsMethodNotAllowed(t *testing.T) {
	config := DeploymentCatalog{}

	req := httptest.NewRequest(http.MethodPost, "/deployments", nil)
	recorder := httptest.NewRecorder()
	config.HandleDeploymentsEndpoint(recorder, req)

	resp := recorder.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}
