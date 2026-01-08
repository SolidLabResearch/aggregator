package config

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTransformationsHead(t *testing.T) {
	config := InstanceConfigData{
		etagTransformations: 7,
		transformations:     "test-transformations",
	}

	req := httptest.NewRequest(http.MethodHead, "/transformations", nil)
	recorder := httptest.NewRecorder()
	config.HandleTransformationsEndpoint(recorder, req)

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

func TestTransformationsGet(t *testing.T) {
	config := InstanceConfigData{
		etagTransformations: 3,
		transformations:     "test-transformations",
	}

	req := httptest.NewRequest(http.MethodGet, "/transformations", nil)
	recorder := httptest.NewRecorder()
	config.HandleTransformationsEndpoint(recorder, req)

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
	if string(body) != "test-transformations" {
		t.Fatalf("unexpected body: %q", string(body))
	}
}

func TestTransformationsMethodNotAllowed(t *testing.T) {
	config := InstanceConfigData{}

	req := httptest.NewRequest(http.MethodPost, "/transformations", nil)
	recorder := httptest.NewRecorder()
	config.HandleTransformationsEndpoint(recorder, req)

	resp := recorder.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}
