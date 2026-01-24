package registration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDeriveSolidBaseURL(t *testing.T) {
	tests := map[string]string{
		"http://rs.local:3000/idp":   "http://rs.local:3000",
		"http://rs.local:3000/.oidc": "http://rs.local:3000",
		"http://rs.local:3000":       "http://rs.local:3000",
	}

	for input, expected := range tests {
		got, err := deriveSolidBaseURL(input)
		if err != nil {
			t.Fatalf("unexpected error for %s: %v", input, err)
		}
		if got != expected {
			t.Fatalf("expected %s, got %s", expected, got)
		}
	}
}

func TestFetchSolidClientCredentials(t *testing.T) {
	const (
		loginToken = "token"
		clientID   = "client-id"
		secret     = "client-secret"
	)

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	mux.HandleFunc("/.account/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		controls := map[string]interface{}{
			"controls": map[string]interface{}{
				"password": map[string]string{
					"login": server.URL + "/login",
				},
				"account": map[string]string{
					"clientCredentials": server.URL + "/creds",
				},
			},
		}
		json.NewEncoder(w).Encode(controls)
	})

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"authorization": loginToken})
	})

	mux.HandleFunc("/creds", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "CSS-Account-Token "+loginToken {
			http.Error(w, "missing account token", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"id": clientID, "secret": secret})
	})

	id, gotSecret, err := fetchSolidClientCredentials(server.URL, "user@example.org", "pass", "client", "http://example.com/webid#me")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != clientID {
		t.Fatalf("expected client id %s, got %s", clientID, id)
	}
	if gotSecret != secret {
		t.Fatalf("expected secret %s, got %s", secret, gotSecret)
	}
}
