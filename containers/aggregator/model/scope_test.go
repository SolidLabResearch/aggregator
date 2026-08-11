package model

import "testing"

func TestAuthorizationScopesAreStoredByResourceAndMethod(t *testing.T) {
	resource := "https://aggregator.example/owner/services/client/train"
	SetAuthorizationScopes(resource, map[string][]Scope{"post": {Execute, Modify}})
	t.Cleanup(func() { DeleteAuthorizationScopes(resource) })

	got := AuthorizationScopes(resource, "POST")
	if len(got) != 2 || got[0] != Execute || got[1] != Modify {
		t.Fatalf("AuthorizationScopes() = %v", got)
	}
	got[0] = Read
	if AuthorizationScopes(resource, "POST")[0] != Execute {
		t.Fatal("AuthorizationScopes returned mutable registry storage")
	}

	DeleteAuthorizationScopes(resource)
	if got := AuthorizationScopes(resource, "POST"); len(got) != 0 {
		t.Fatalf("scopes remained after deletion: %v", got)
	}
}
