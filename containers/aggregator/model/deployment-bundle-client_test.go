package model

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func testDeploymentBundle() *DeploymentBundle {
	manifest := runtime.RawExtension{Raw: []byte(`{
      "apiVersion":"apps/v1","kind":"Deployment",
      "spec":{"template":{"spec":{"containers":[{
        "name":"fetch","image":"fetch","ports":[{"name":"http","containerPort":8080}]
      }]}}}
    }`)}
	return &DeploymentBundle{
		APIVersion: DeploymentBundleAPIVersion,
		Kind:       DeploymentBundleKind,
		DeploymentFunction: BundledDeploymentFunction{ObjectMeta: metav1.ObjectMeta{Name: "fetch-profiled"}, Spec: BundledDeploymentFunctionSpec{
			Function: BundledDeploymentSignature{
				Expects: []BundledDeploymentParameter{{Name: "url", Predicate: "url", Type: "xsd:anyURI", Required: true}},
				Returns: BundledDeploymentOutput{Name: "deployedService", Predicate: "service"},
			},
			ProfileRef: &BundledLocalReference{Name: "fetch"},
			Orchestration: BundledOrchestration{
				Resources: []BundledResource{{ID: "workload", Manifest: manifest}},
				InputBindings: []BundledInputBinding{{Parameter: "url", Targets: []BundledEnvironmentBinding{
					{Resource: "workload", Container: "fetch", Env: "GET_URL"},
				}}},
				RouteBindings: BundledRouteBindings{Distributions: map[string]map[string]BundledRouteTarget{
					"fetched-content": {"content": {Resource: "workload", Container: "fetch", Port: "http", InternalPath: "/"}},
				}},
			},
		}},
		Profile: &BundledProfile{ObjectMeta: metav1.ObjectMeta{Name: "fetch"}, Spec: BundledProfileSpec{
			ServiceProfile: &BundledServiceProfile{Title: "Fetch service", AccessRoles: map[string]BundledAccessRole{"reader": {Title: "Content reader"}}},
			DatasetProfiles: map[string]BundledDatasetProfile{
				"fetched-content": {Title: "Fetched content", Distributions: map[string]BundledDistributionProfile{
					"content": {Path: "/content", URLType: "accessURL", AccessRoles: []string{"reader"}},
				}},
			},
		}},
	}
}

func TestFetchDeploymentBundle(t *testing.T) {
	bundle := testDeploymentBundle()
	body, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != "/internal/deployment-functions/fetch-profiled" {
			t.Fatalf("unexpected request path %q", request.URL.Path)
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(string(body))), Header: http.Header{}}, nil
	})}

	oldURL, oldClient := AggregatorServerInternalURL, HttpClient
	AggregatorServerInternalURL, HttpClient = "http://aggregator-server-svc:5001", client
	t.Cleanup(func() { AggregatorServerInternalURL, HttpClient = oldURL, oldClient })

	result, err := FetchDeploymentBundle(context.Background(), "fetch-profiled")
	if err != nil {
		t.Fatalf("FetchDeploymentBundle: %v", err)
	}
	if result.DeploymentFunction.Name != "fetch-profiled" || result.Profile == nil || result.Profile.Name != "fetch" {
		t.Fatalf("unexpected bundle: %#v", result)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestResolveProfiledFetchBundle(t *testing.T) {
	oldProtocol, oldHost, oldPort := ExternalProto, ExternalHost, ExternalPort
	ExternalProto, ExternalHost, ExternalPort = "http", "aggregator.example", "80"
	t.Cleanup(func() { ExternalProto, ExternalHost, ExternalPort = oldProtocol, oldHost, oldPort })

	functionURI := "http://aggregator.example/deployments/fetch-profiled"
	definition, err := ResolveDeploymentBundle(functionURI, testDeploymentBundle())
	if err != nil {
		t.Fatalf("AdaptDeploymentBundle: %v", err)
	}
	if len(definition.Parameters) != 1 || definition.Parameters[0].Predicate != functionURI+"#url" || !definition.Parameters[0].Required {
		t.Fatalf("unexpected parameters: %#v", definition.Parameters)
	}
	if definition.ProfileURI != "http://aggregator.example/profiles/fetch" {
		t.Fatalf("unexpected profile URI %q", definition.ProfileURI)
	}
	dataset := definition.Datasets["fetched-content"]
	if dataset.ProfileURI != "http://aggregator.example/profiles/fetch#dataset-fetched-content" {
		t.Fatalf("unexpected dataset profile URI %q", dataset.ProfileURI)
	}
	distribution := dataset.Distributions["content"]
	if distribution.Target.Port != 8080 || distribution.Path != "/content" {
		t.Fatalf("unexpected distribution: %#v", distribution)
	}
	if len(distribution.AccessRoles) != 1 || distribution.AccessRoles[0] != "reader" {
		t.Fatalf("unexpected distribution access roles: %v", distribution.AccessRoles)
	}
	if definition.ServiceProfile.AccessRoles["reader"].URI != "http://aggregator.example/profiles/fetch#role-reader" {
		t.Fatalf("unexpected resolved role: %#v", definition.ServiceProfile.AccessRoles["reader"])
	}
	if len(definition.InputBindings) != 1 || definition.InputBindings[0].Targets[0].Env != "GET_URL" {
		t.Fatalf("unexpected input bindings: %#v", definition.InputBindings)
	}
}

func TestResolveAcceptsMultipleResources(t *testing.T) {
	bundle := testDeploymentBundle()
	bundle.DeploymentFunction.Spec.Orchestration.Resources = append(bundle.DeploymentFunction.Spec.Orchestration.Resources,
		BundledResource{ID: "settings", Manifest: runtime.RawExtension{Raw: []byte(`{"apiVersion":"v1","kind":"ConfigMap","data":{"mode":"test"}}`)}})
	definition, err := ResolveDeploymentBundle("https://aggregator.example/deployments/fetch", bundle)
	if err != nil {
		t.Fatalf("ResolveDeploymentBundle: %v", err)
	}
	if len(definition.Resources) != 2 || definition.Resources[1].Kind != "ConfigMap" {
		t.Fatalf("unexpected resources: %#v", definition.Resources)
	}
}

func TestResolveOperationalEndpoint(t *testing.T) {
	bundle := testDeploymentBundle()
	bundle.Profile.Spec.ServiceProfile.Endpoints = map[string]BundledEndpoint{
		"refresh": {Path: "/refresh", Operations: []BundledOperation{{
			Method: http.MethodPost, Executes: "fetch", AccessRoles: []string{"reader"},
			Updates: &BundledOperationUpdate{Function: "fetch", Parameters: []string{"source"}},
		}}},
	}
	bundle.DeploymentFunction.Spec.Orchestration.RouteBindings.Endpoints = map[string]BundledRouteTarget{
		"refresh": {Resource: "workload", Container: "fetch", Port: "http", InternalPath: "/refresh"},
	}
	definition, err := ResolveDeploymentBundle("https://aggregator.example/deployments/fetch", bundle)
	if err != nil {
		t.Fatalf("ResolveDeploymentBundle: %v", err)
	}
	endpoint := definition.Endpoints["refresh"]
	if endpoint.Path != "/refresh" || endpoint.Target.Port != 8080 || len(endpoint.Operations) != 1 || endpoint.Operations[0].Executes != "fetch" {
		t.Fatalf("unexpected endpoint: %#v", endpoint)
	}
	operation := endpoint.Operations[0]
	if len(operation.Scopes) != 2 || operation.Scopes[0] != Execute || operation.Scopes[1] != Modify {
		t.Fatalf("unexpected semantic scopes: %#v", operation.Scopes)
	}
	if len(operation.AccessRoles) != 1 || operation.AccessRoles[0] != "reader" {
		t.Fatalf("unexpected operation access roles: %v", operation.AccessRoles)
	}
}
