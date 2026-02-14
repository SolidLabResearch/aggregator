package registration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"aggregator/model"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestFindClientIDByURI(t *testing.T) {
	var mu sync.Mutex
	gotMethod := ""

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotMethod = r.Method
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]string{
			{
				"id":  "client-123",
				"uri": "http://example.org",
			},
		})
	}))
	defer server.Close()

	cfg := &umaConfig{RegistrationEndpoint: server.URL}
	id, err := findClientIDByURI(cfg, "token", "http://example.org")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if id != "client-123" {
		t.Fatalf("expected client-123, got %q", id)
	}

	mu.Lock()
	method := gotMethod
	mu.Unlock()
	if method != http.MethodGet {
		t.Fatalf("expected GET request, got %q", method)
	}
}

func TestFindClientIDByURI_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]string{
			{
				"id":  "client-123",
				"uri": "http://other.example",
			},
		})
	}))
	defer server.Close()

	cfg := &umaConfig{RegistrationEndpoint: server.URL}
	_, err := findClientIDByURI(cfg, "token", "http://example.org")
	if err == nil {
		t.Fatal("expected error for missing client URI, got nil")
	}
}

func TestEnsurePATForUMA_ConflictDeletesAndReRegisters(t *testing.T) {
	originalClientset := model.Clientset
	t.Cleanup(func() {
		model.Clientset = originalClientset
	})
	model.Clientset = fake.NewSimpleClientset()

	clientURI := "http://aggregator.local:5000"
	existingID := "existing-client"

	var mu sync.Mutex
	var deleteID string
	registerCalls := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/register" && r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]map[string]string{
				{
					"id":  existingID,
					"uri": clientURI,
				},
			})
			return
		case r.URL.Path == "/register" && r.Method == http.MethodPost:
			mu.Lock()
			if registerCalls == 0 {
				registerCalls++
				mu.Unlock()
				http.Error(w, "conflict", http.StatusConflict)
				return
			}
			registerCalls++
			mu.Unlock()

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"client_id":                  "new-client",
				"client_secret":              "new-secret",
				"token_endpoint_auth_method": "client_secret_basic",
			})
			return
		case strings.HasPrefix(r.URL.Path, "/register/") && r.Method == http.MethodDelete:
			mu.Lock()
			deleteID = strings.TrimPrefix(r.URL.Path, "/register/")
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		case r.URL.Path == "/token" && r.Method == http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "pat-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
			return
		default:
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
	}))
	defer server.Close()

	cfg := &umaConfig{
		RegistrationEndpoint: server.URL + "/register",
		TokenEndpoint:        server.URL + "/token",
	}

	clientID, clientSecret, pat, err := ensurePATForUMA(context.Background(), cfg, "bearer-token", clientURI)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if clientID != "new-client" {
		t.Fatalf("expected new client ID, got %q", clientID)
	}
	if clientSecret != "new-secret" {
		t.Fatalf("expected new client secret, got %q", clientSecret)
	}
	if pat == nil || pat.AccessToken != "pat-token" {
		t.Fatalf("expected pat-token, got %#v", pat)
	}

	mu.Lock()
	calls := registerCalls
	deleted := deleteID
	mu.Unlock()
	if calls != 2 {
		t.Fatalf("expected 2 registration attempts, got %d", calls)
	}
	if deleted != existingID {
		t.Fatalf("expected delete of %q, got %q", existingID, deleted)
	}

	secret, err := model.Clientset.CoreV1().Secrets(aggregatorConfigNamespace).Get(context.Background(), provisionUMASecretName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected secret to be stored, got %v", err)
	}
	if string(secret.Data[provisionUMAClientIDKey]) != "new-client" {
		t.Fatalf("expected stored client ID, got %q", string(secret.Data[provisionUMAClientIDKey]))
	}
	if string(secret.Data[provisionUMAClientSecretKey]) != "new-secret" {
		t.Fatalf("expected stored client secret, got %q", string(secret.Data[provisionUMAClientSecretKey]))
	}
}
