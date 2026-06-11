package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func withAuthMocks(t *testing.T, fetch func(map[string][]string, string) (string, error), verify func(string, []string) ([]Permission, error)) {
	t.Helper()
	oldFetch := fetchTicketForIssuer
	oldVerify := verifyTicketForToken
	oldIndex := idIndex

	fetchTicketForIssuer = fetch
	verifyTicketForToken = verify
	idIndex = make(map[string]string)

	t.Cleanup(func() {
		fetchTicketForIssuer = oldFetch
		verifyTicketForToken = oldVerify
		idIndex = oldIndex
	})
}

func TestBuildPermissionsUsesAggregatorSpecScopes(t *testing.T) {
	oldIndex := idIndex
	idIndex = make(map[string]string)
	t.Cleanup(func() {
		idIndex = oldIndex
	})

	tests := []struct {
		method string
		scope  string
	}{
		{method: http.MethodGet, scope: string(ScopeRead)},
		{method: http.MethodHead, scope: string(ScopeRead)},
		{method: http.MethodPost, scope: string(ScopeCreate)},
		{method: http.MethodPut, scope: string(ScopeWrite)},
		{method: http.MethodPatch, scope: string(ScopeWrite)},
		{method: http.MethodDelete, scope: string(ScopeDelete)},
	}

	for _, test := range tests {
		permission := BuildPermissions("http://example.test/resource", test.method)
		if len(permission.ResourceScopes) != 1 || permission.ResourceScopes[0] != test.scope {
			t.Fatalf("expected %s to require %q, got %#v", test.method, test.scope, permission.ResourceScopes)
		}
	}
}

func TestBuildPermissionsUsesRegisteredUmaResourceID(t *testing.T) {
	oldIndex := idIndex
	idIndex = map[string]string{"http://aggregator.example/service": "resource-10"}
	t.Cleanup(func() {
		idIndex = oldIndex
	})

	permission := BuildPermissions("http://aggregator.example/service", http.MethodGet)
	if permission.ResourceID != "resource-10" {
		t.Fatalf("expected registered UMA resource id, got %q", permission.ResourceID)
	}
	if len(permission.ResourceScopes) != 1 || permission.ResourceScopes[0] != string(ScopeRead) {
		t.Fatalf("unexpected scopes: %#v", permission.ResourceScopes)
	}
}

func TestAuthorizeRequestReturnsUMATicketChallengeWhenAuthorizationMissing(t *testing.T) {
	withAuthMocks(t,
		func(permissions map[string][]string, issuer string) (string, error) {
			if issuer != AS_ISSUER {
				t.Fatalf("unexpected issuer %q", issuer)
			}
			if _, ok := permissions["http://aggregator.example/service"]; ok {
				t.Fatalf("ticket request should use registered UMA id, got %#v", permissions)
			}
			scopes := permissions["resource-10"]
			if len(scopes) != 1 || scopes[0] != string(ScopeRead) {
				t.Fatalf("unexpected requested permissions: %#v", permissions)
			}
			return "ticket-1", nil
		},
		func(string, []string) ([]Permission, error) {
			t.Fatal("verify should not be called without an Authorization header")
			return nil, nil
		},
	)
	idIndex["http://aggregator.example/service"] = "resource-10"

	request := httptest.NewRequest(http.MethodGet, "http://aggregator.example/service", nil)
	response := httptest.NewRecorder()

	if AuthorizeRequest(response, request, nil) {
		t.Fatal("request should not be authorized")
	}
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", response.Code)
	}
	expected := `UMA as_uri="http://localhost:4000/uma", ticket="ticket-1"`
	if response.Header().Get("WWW-Authenticate") != expected {
		t.Fatalf("unexpected WWW-Authenticate header: %q", response.Header().Get("WWW-Authenticate"))
	}
}

func TestAuthorizeRequestReturnsUMATicketChallengeWhenTokenInvalid(t *testing.T) {
	withAuthMocks(t,
		func(map[string][]string, string) (string, error) {
			return "ticket-2", nil
		},
		func(string, []string) ([]Permission, error) {
			return nil, errors.New("invalid token")
		},
	)

	request := httptest.NewRequest(http.MethodGet, "http://aggregator.example/service", nil)
	request.Header.Set("Authorization", "Bearer invalid")
	response := httptest.NewRecorder()

	if AuthorizeRequest(response, request, nil) {
		t.Fatal("request should not be authorized")
	}
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", response.Code)
	}
	if response.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("expected UMA WWW-Authenticate challenge")
	}
}

func TestAuthorizeRequestReturnsUMATicketChallengeWhenScopeInsufficient(t *testing.T) {
	withAuthMocks(t,
		func(map[string][]string, string) (string, error) {
			return "ticket-3", nil
		},
		func(string, []string) ([]Permission, error) {
			return []Permission{{
				ResourceID:     "uma-service",
				ResourceScopes: []string{string(ScopeRead)},
			}}, nil
		},
	)
	idIndex["http://aggregator.example/service"] = "uma-service"

	request := httptest.NewRequest(http.MethodDelete, "http://aggregator.example/service", nil)
	request.Header.Set("Authorization", "Bearer rpt")
	response := httptest.NewRecorder()

	if AuthorizeRequest(response, request, nil) {
		t.Fatal("request should not be authorized")
	}
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", response.Code)
	}
	if response.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("expected UMA WWW-Authenticate challenge")
	}
}

func TestCheckPermissionAcceptsLegacyScopeAliases(t *testing.T) {
	oldIndex := idIndex
	idIndex = map[string]string{"http://aggregator.example/service": "uma-service"}
	t.Cleanup(func() {
		idIndex = oldIndex
	})

	ok := CheckPermission("http://aggregator.example/service", http.MethodGet, []Permission{{
		ResourceID:     "uma-service",
		ResourceScopes: []string{string(legacyScopeRead)},
	}})
	if !ok {
		t.Fatal("expected legacy read scope to be accepted")
	}
}
