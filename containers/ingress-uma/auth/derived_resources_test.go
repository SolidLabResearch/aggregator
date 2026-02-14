package auth

import (
	"testing"
)

func TestDerivedResourceIDs_ServiceLocation(t *testing.T) {
	originalHost := ExternalHost
	ExternalHost = "aggregator.local:5000"
	t.Cleanup(func() {
		ExternalHost = originalHost
	})

	ids := derivedResourceIDs("/services/ns-123/svc-456")
	expected := []string{
		"http://aggregator.local:5000/services/ns-123/svc-456",
		"http://aggregator.local:5000/config/ns-123",
		"http://aggregator.local:5000/config/ns-123/services",
		"http://aggregator.local:5000/config/ns-123/transformations",
		"http://aggregator.local:5000/config/ns-123/services/svc-456",
	}

	assertStringSetEqual(t, ids, expected)
}

func TestDeriveOwnerWebID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "http://rs.local:3000/alice/profile/card#me",
			expected: "http://rs.local:3000/alice/profile/card#me",
		},
		{
			input:    "http://rs.local:3000/alice/profile/card",
			expected: "http://rs.local:3000/alice/profile/card#me",
		},
		{
			input:    "http://rs.local:3000/alice",
			expected: "http://rs.local:3000/alice/profile/card#me",
		},
	}

	for _, test := range tests {
		if got := deriveOwnerWebID(test.input); got != test.expected {
			t.Fatalf("expected %q for %q, got %q", test.expected, test.input, got)
		}
	}
}

func assertStringSetEqual(t *testing.T, got []string, expected []string) {
	t.Helper()
	if len(got) != len(expected) {
		t.Fatalf("expected %d entries, got %d", len(expected), len(got))
	}

	seen := make(map[string]struct{}, len(got))
	for _, entry := range got {
		seen[entry] = struct{}{}
	}

	for _, entry := range expected {
		if _, ok := seen[entry]; !ok {
			t.Fatalf("expected %q in set, got %v", entry, got)
		}
	}
}
