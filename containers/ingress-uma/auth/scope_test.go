package auth

import "testing"

func TestDetermineScopes(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		available []Scope
		want      Scope
	}{
		{name: "get", method: "GET", want: Read},
		{name: "head", method: "HEAD", want: Read},
		{name: "post operational endpoint", method: "POST", available: []Scope{Read, Write}, want: Write},
		{name: "post collection", method: "POST", available: []Scope{Read, Create}, want: Create},
		{name: "put", method: "PUT", want: Write},
		{name: "patch", method: "PATCH", want: Write},
		{name: "delete", method: "DELETE", want: Delete},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := determineScopes(test.method, test.available)
			if err != nil {
				t.Fatalf("determineScopes(%q): %v", test.method, err)
			}
			if len(got) != 1 || got[0] != test.want {
				t.Fatalf("determineScopes(%q) = %v, want [%s]", test.method, got, test.want)
			}
		})
	}
}

func TestDetermineScopesRejectsUnsupportedMethod(t *testing.T) {
	if _, err := determineScopes("OPTIONS", nil); err == nil {
		t.Fatal("determineScopes(OPTIONS) unexpectedly succeeded")
	}
}
