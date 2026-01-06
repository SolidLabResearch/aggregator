package registration

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDiscoverIDPFromWebID_Turtle(t *testing.T) {
	// Create a mock WebID server returning Turtle format
	webIDContent := `@prefix solid: <http://www.w3.org/ns/solid/terms#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .

<#me>
    a foaf:Person ;
    foaf:name "Alice" ;
    solid:oidcIssuer <https://idp.example.com> .
`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/turtle")
		w.Write([]byte(webIDContent))
	}))
	defer server.Close()

	webID := server.URL + "#me"

	issuer, err := discoverIDPFromWebID(webID)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	expectedIssuer := "https://idp.example.com"
	if issuer != expectedIssuer {
		t.Errorf("Expected issuer %s, got %s", expectedIssuer, issuer)
	}
}

func TestDiscoverIDPFromWebID_NotFound(t *testing.T) {
	// Create a mock WebID server without oidcIssuer
	webIDContent := `@prefix foaf: <http://xmlns.com/foaf/0.1/> .

<#me>
    a foaf:Person ;
    foaf:name "Charlie" .
`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/turtle")
		w.Write([]byte(webIDContent))
	}))
	defer server.Close()

	webID := server.URL + "#me"

	_, err := discoverIDPFromWebID(webID)
	if err == nil {
		t.Fatal("Expected error when oidcIssuer not found, got nil")
	}
}

func TestDiscoverIDPFromWebID_HTTPError(t *testing.T) {
	// Create a mock server that returns 404
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	webID := server.URL + "#me"

	_, err := discoverIDPFromWebID(webID)
	if err == nil {
		t.Fatal("Expected error for 404 response, got nil")
	}
}
