package auth

import (
	"bytes"
	"encoding/json"
	"ingress-uma/model"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestDefaultPolicyLifecycleWithoutResources(t *testing.T) {
	resetDefaultPolicyTestState(t)
	body, _ := json.Marshal(defaultPolicyRequest{
		AggregatorID: "agg-1", UserID: "owner", ASURL: "https://uma.example",
		Assigner: "owner", Document: json.RawMessage(testPolicyDocument),
	})
	request := httptest.NewRequest(http.MethodPost, "/default-policies", bytes.NewReader(body))
	response := httptest.NewRecorder()
	HandleDefaultPolicyRequest(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("POST status = %d, body = %s", response.Code, response.Body.String())
	}
	var created DefaultPolicy
	if err := json.NewDecoder(response.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if created.ID == "" || !strings.Contains(string(created.Document), "reader") {
		t.Fatalf("unexpected policy: %#v", created)
	}

	request = httptest.NewRequest(http.MethodGet, "/default-policies?aggregator_id=agg-1", nil)
	response = httptest.NewRecorder()
	HandleDefaultPolicyRequest(response, request)
	var policies []DefaultPolicy
	if err := json.NewDecoder(response.Body).Decode(&policies); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || len(policies) != 1 || policies[0].ID != created.ID {
		t.Fatalf("unexpected policy list: status=%d policies=%#v", response.Code, policies)
	}

	request = httptest.NewRequest(http.MethodDelete, "/default-policies?aggregator_id=agg-1&id="+created.ID, nil)
	response = httptest.NewRecorder()
	HandleDefaultPolicyRequest(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("DELETE status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestNewResourceReceivesDefaultPolicy(t *testing.T) {
	resetDefaultPolicyTestState(t)
	request := defaultPolicyRequest{
		AggregatorID: "agg-1", UserID: "owner", ASURL: "https://uma.example",
		Assigner: "owner", Document: json.RawMessage(testPolicyDocument),
	}
	set := ensureDefaultPolicySet(request)
	defaultPoliciesMu.Lock()
	set.Policies["policy-1"] = DefaultPolicy{ID: "policy-1", Document: json.RawMessage(testPolicyDocument)}
	defaultPoliciesMu.Unlock()

	var posted string
	originalClient := modelHTTPClientForTests(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodGet && strings.HasPrefix(req.URL.String(), "http://token-service:8080/token") {
			return testHTTPResponse(http.StatusOK, `{"id_token":"owner-token"}`), nil
		}
		if req.Method == http.MethodPost && req.URL.String() == "https://uma.example/policies" {
			data := new(bytes.Buffer)
			_, _ = data.ReadFrom(req.Body)
			posted = data.String()
			return testHTTPResponse(http.StatusCreated, `{}`), nil
		}
		t.Fatalf("unexpected request: %s %s", req.Method, req.URL)
		return nil, nil
	}))
	defer originalClient()

	data := ResourceData{
		UmaID: "uma-resource-1",
		AggData: AggregatorAuthData{
			AggregatorID: "agg-1", UserID: "owner", AuthzServer: "https://uma.example",
		},
		Scopes: []Scope{Read, Write},
	}
	resourceIndexMu.Lock()
	resourceIndex["https://aggregator.example/services/1"] = data
	resourceIndexMu.Unlock()
	if err := instantiateDefaultsForResource("https://aggregator.example/services/1", data); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{OdrlPrefix + "read", OdrlPrefix + "write", "http://example.com/id/uma-resource-1", "http://example.com/id/reader", "https://example.org/constraint", "FR-HDF"} {
		if !strings.Contains(posted, expected) {
			t.Fatalf("generated policy does not contain %q:\n%s", expected, posted)
		}
	}
	permissionLink := regexp.MustCompile(`<urn:uuid:[^>]+> <http://www.w3.org/ns/odrl/2/permission> <urn:uuid:[^>]+>`)
	if !permissionLink.MatchString(posted) {
		t.Fatalf("policy permission is not a named node:\n%s", posted)
	}
	if count := strings.Count(posted, `<http://www.w3.org/ns/odrl/2/uid>`); count != 2 {
		t.Fatalf("generated policy has %d uid statements, want 2:\n%s", count, posted)
	}
	if strings.Contains(posted, "_:") {
		t.Fatalf("generated policy contains a blank node:\n%s", posted)
	}
}

func TestValidateDefaultPolicyRejectsAggregatorManagedFields(t *testing.T) {
	for _, field := range []string{"target", "action", "assigner"} {
		document := strings.Replace(testPolicyDocument, `"assignee":"reader"`, `"assignee":"reader","`+field+`":"forbidden"`, 1)
		if err := validateDefaultPolicy(json.RawMessage(document)); err == nil {
			t.Fatalf("expected %s to be rejected", field)
		}
	}
}

func TestPolicyManagementResourceIdentification(t *testing.T) {
	tests := []struct {
		resource string
		want     bool
	}{
		{"https://aggregator.example/agg-1/policies", true},
		{"https://aggregator.example/agg-1/policies/policy-1", true},
		{"https://aggregator.example/agg-1/services", false},
		{"https://aggregator.example/other/policies", false},
		{"https://aggregator.example/agg-1/services/policies", false},
	}
	for _, test := range tests {
		if got := isPolicyManagementResource(test.resource, "agg-1"); got != test.want {
			t.Errorf("isPolicyManagementResource(%q) = %v, want %v", test.resource, got, test.want)
		}
	}
}

func TestOnlyOwnerPolicyAppliesToPolicyManagementResources(t *testing.T) {
	resource := "https://aggregator.example/agg-1/policies"
	ordinary := DefaultPolicy{ID: "ordinary"}
	owner := DefaultPolicy{ID: "owner", PolicyManagement: true}
	if _, applies := policyActionsForResource(ordinary, resource, "agg-1", []Scope{Read}); applies {
		t.Fatal("ordinary default policy applies to policy management")
	}
	if _, applies := policyActionsForResource(owner, resource, "agg-1", []Scope{Read}); !applies {
		t.Fatal("owner policy does not apply to policy management")
	}
	if _, applies := policyActionsForResource(ordinary, "https://aggregator.example/agg-1/services", "agg-1", []Scope{Read}); !applies {
		t.Fatal("ordinary default policy does not apply to service resource")
	}
}

func TestRoleGrantSelectsExactResourceActions(t *testing.T) {
	resource := "https://aggregator.example/agg-1/services/client/train"
	policy := DefaultPolicy{Selector: &PolicySelector{Service: "https://aggregator.example/agg-1/services/client", Role: "https://aggregator.example/profiles/client#role-coordinator", Resources: map[string][]Scope{resource: {Execute}}}}
	actions, applies := policyActionsForResource(policy, resource, "agg-1", []Scope{Execute, Modify})
	if !applies || len(actions) != 1 || actions[0] != Execute {
		t.Fatalf("selected actions = %v, applies = %v", actions, applies)
	}
	if _, applies := policyActionsForResource(policy, resource+"/other", "agg-1", []Scope{Read}); applies {
		t.Fatal("role grant applied outside selected resources")
	}
}

const testPolicyDocument = `{
  "@context": {
    "odrl": "http://www.w3.org/ns/odrl/2/",
    "ex": "https://example.org/",
    "Agreement": "odrl:Agreement",
    "Permission": "odrl:Permission",
    "uid": "@id",
    "permission": "odrl:permission",
    "assignee": {"@id":"odrl:assignee", "@type":"@id"},
    "assigner": {"@id":"odrl:assigner", "@type":"@id"},
    "target": {"@id":"odrl:target", "@type":"@id"},
    "action": {"@id":"odrl:action", "@type":"@id"}
  },
  "@type":"Agreement",
  "uid":"https://example.org/policies/template",
  "permission":[{
    "@type":"Permission",
    "assignee":"reader",
    "ex:constraint":[{"ex:leftOperand":"country","ex:rightOperand":["FR-HDF","BE-BRU"]}]
  }]
}`

func resetDefaultPolicyTestState(t *testing.T) {
	t.Helper()
	defaultPoliciesMu.Lock()
	originalPolicies := defaultPolicies
	defaultPolicies = map[string]*defaultPolicySet{}
	defaultPoliciesMu.Unlock()
	resourceIndexMu.Lock()
	originalResources := resourceIndex
	resourceIndex = map[string]ResourceData{}
	resourceIndexMu.Unlock()
	t.Cleanup(func() {
		defaultPoliciesMu.Lock()
		defaultPolicies = originalPolicies
		defaultPoliciesMu.Unlock()
		resourceIndexMu.Lock()
		resourceIndex = originalResources
		resourceIndexMu.Unlock()
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func modelHTTPClientForTests(t *testing.T, transport http.RoundTripper) func() {
	t.Helper()
	original := model.HttpClient
	model.HttpClient = &http.Client{Transport: transport}
	return func() { model.HttpClient = original }
}

func testHTTPResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{},
	}
}
