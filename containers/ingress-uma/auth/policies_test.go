package auth

import (
	"reflect"
	"strings"
	"testing"
)

func TestActionList_DedupesAndFormats(t *testing.T) {
	actions := actionList([]Scope{Read, Create, Write, Read})
	expected := []string{"odrl:read", "odrl:modify"}
	if !reflect.DeepEqual(actions, expected) {
		t.Fatalf("expected %v, got %v", expected, actions)
	}
}

func TestBuildPolicyBody_IncludesAssignments(t *testing.T) {
	resourceID := "http://example.org/resource"
	userID := "http://example.org/user#me"
	assignerID := "http://example.org/assigner#me"

	body := buildPolicyBody(resourceID, []Scope{Read, Create}, userID, assignerID)

	if !strings.Contains(body, "odrl:action odrl:read, odrl:modify") {
		t.Fatalf("expected action list in policy body, got %s", body)
	}
	if !strings.Contains(body, "odrl:target <"+resourceID+">") {
		t.Fatalf("expected target %s in policy body", resourceID)
	}
	if !strings.Contains(body, "odrl:assignee <"+userID+">") {
		t.Fatalf("expected assignee %s in policy body", userID)
	}
	if !strings.Contains(body, "odrl:assigner <"+assignerID+">") {
		t.Fatalf("expected assigner %s in policy body", assignerID)
	}
}

func TestBuildPolicyBody_DefaultRead(t *testing.T) {
	body := buildPolicyBody("http://example.org/resource", nil, "http://example.org/user#me", "http://example.org/assigner#me")
	if !strings.Contains(body, "odrl:action odrl:read") {
		t.Fatalf("expected default read action, got %s", body)
	}
}

func TestWebIDFromAuthHeader(t *testing.T) {
	header := "WebID http%3A%2F%2Fexample.org%2Fprofile%2Fcard%23me"
	webID := webIDFromAuthHeader(header)
	if webID != "http://example.org/profile/card#me" {
		t.Fatalf("expected decoded WebID, got %q", webID)
	}

	if webIDFromAuthHeader("Bearer token") != "" {
		t.Fatalf("expected empty WebID for non-WebID header")
	}
}
