package config

import "testing"

func TestPolicyOwnerWebID_ProvisionOverrides(t *testing.T) {
	t.Setenv("REGISTRATION_TYPE", "provision")
	t.Setenv("PROVISION_WEBID", "http://example.org/provision#me")

	got := policyOwnerWebID("http://example.org/fallback#me")
	if got != "http://example.org/provision#me" {
		t.Fatalf("expected provision webid, got %q", got)
	}
}

func TestPolicyOwnerWebID_ProvisionMissingFallsBack(t *testing.T) {
	t.Setenv("REGISTRATION_TYPE", "provision")
	t.Setenv("PROVISION_WEBID", "")

	got := policyOwnerWebID("http://example.org/fallback#me")
	if got != "http://example.org/fallback#me" {
		t.Fatalf("expected fallback webid, got %q", got)
	}
}

func TestPolicyOwnerWebID_NonProvisionUsesFallback(t *testing.T) {
	t.Setenv("REGISTRATION_TYPE", "none")
	t.Setenv("PROVISION_WEBID", "http://example.org/provision#me")

	got := policyOwnerWebID("http://example.org/fallback#me")
	if got != "http://example.org/fallback#me" {
		t.Fatalf("expected fallback webid, got %q", got)
	}
}
