package catalog

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/maartyman/rdfgo"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func fetchProfile() Profile {
	return Profile{
		ObjectMeta: metav1.ObjectMeta{Name: "fetch", Namespace: "aggregator-platform"},
		Spec: ProfileSpec{
			ServiceProfile: &ServiceProfile{
				Title:       "Fetch service",
				AccessRoles: map[string]AccessRole{"reader": {Title: "Content reader"}},
				Parameters:  map[string]Parameter{"source": {Predicate: "source", Type: "xsd:anyURI", Required: true}},
				Outputs:     map[string]Output{"content": {Predicate: "content", DatasetProfile: DatasetReference{Dataset: "fetched-content"}}},
				Functions:   map[string]Function{"fetch": {Name: "Fetch remote content", Expects: []string{"source"}, Returns: []string{"content"}}},
			},
			DatasetProfiles: map[string]DatasetProfile{
				"fetched-content": {Title: "Fetched content", Distributions: map[string]DistributionProfile{
					"content": {Path: "/content", URLType: "accessURL", AccessRoles: []string{"reader"}},
				}},
			},
		},
	}
}

func fetchDeployment(name string, profiled bool) DeploymentFunction {
	manifest := runtime.RawExtension{Raw: []byte(`{
        "apiVersion":"apps/v1","kind":"Deployment",
        "spec":{"template":{"spec":{"containers":[{"name":"fetch","image":"fetch","ports":[{"name":"http","containerPort":8080}]}]}}}
    }`)}
	definition := DeploymentFunction{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "aggregator-platform"},
		Spec: DeploymentFunctionSpec{
			Function: DeploymentSignature{
				Title:   "Deploy fetch service",
				Expects: []DeploymentParameter{{Name: "url", Predicate: "url", Type: "xsd:anyURI", Required: true}},
				Returns: DeploymentOutput{Name: "deployedService", Predicate: "service"},
			},
			Orchestration: Orchestration{
				Resources:     []OrchestrationResource{{ID: "workload", Manifest: manifest}},
				InputBindings: []InputBinding{{Parameter: "url", Targets: []EnvironmentBinding{{Resource: "workload", Container: "fetch", Env: "GET_URL"}}}},
				RouteBindings: RouteBindings{Distributions: map[string]map[string]RouteTarget{
					"fetched-content": {"content": {Resource: "workload", Container: "fetch", Port: "http", InternalPath: "/"}},
				}},
			},
		},
	}
	if profiled {
		definition.Spec.ProfileRef = &LocalReference{Name: "fetch"}
	} else {
		definition.Spec.Interface = &InlineInterface{Datasets: fetchProfile().Spec.DatasetProfiles}
	}
	return definition
}

func TestCompileProfileUsesDocumentScopedURIs(t *testing.T) {
	rdf, err := CompileProfile(ptr(fetchProfile()), URLs{Server: "https://aggregator.example"})
	if err != nil {
		t.Fatalf("CompileProfile: %v", err)
	}
	text := string(rdf)
	assertValidTurtle(t, text)
	for _, expected := range []string{
		"<https://aggregator.example/profiles/fetch>",
		"<https://aggregator.example/profiles/fetch#source>",
		"<https://aggregator.example/profiles/fetch#dataset-fetched-content>",
		"<https://aggregator.example/profiles/fetch#role-reader>",
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("compiled profile does not contain %s", expected)
		}
	}
}

func TestValidationRejectsUnknownAccessRole(t *testing.T) {
	profile := fetchProfile()
	dataset := profile.Spec.DatasetProfiles["fetched-content"]
	distribution := dataset.Distributions["content"]
	distribution.AccessRoles = []string{"missing"}
	dataset.Distributions["content"] = distribution
	profile.Spec.DatasetProfiles["fetched-content"] = dataset
	if err := ValidateProfile(&profile); err == nil || !strings.Contains(err.Error(), "unknown access role") {
		t.Fatalf("expected unknown access role error, got %v", err)
	}
}

func TestCompileDeploymentAddsConformanceOnlyForProfiledService(t *testing.T) {
	profile := fetchProfile()
	profiled := fetchDeployment("fetch-profiled", true)
	rdf, err := CompileDeploymentFunction(&profiled, &profile, URLs{Server: "https://aggregator.example"})
	if err != nil {
		t.Fatalf("compile profiled function: %v", err)
	}
	if !strings.Contains(string(rdf), "<https://aggregator.example/deployments/fetch-profiled#url>") {
		t.Fatal("missing short predicate URI")
	}
	assertValidTurtle(t, string(rdf))
	if !strings.Contains(string(rdf), "<https://aggregator.example/profiles/fetch>") {
		t.Fatal("missing profile conformance")
	}

	unprofiled := fetchDeployment("fetch-unprofiled", false)
	rdf, err = CompileDeploymentFunction(&unprofiled, nil, URLs{Server: "https://aggregator.example"})
	if err != nil {
		t.Fatalf("compile unprofiled function: %v", err)
	}
	if strings.Contains(string(rdf), "conformsTo") {
		t.Fatal("unprofiled output unexpectedly conforms to a profile")
	}
}

func TestInternalEndpointIsNotRegisteredOnPublicMux(t *testing.T) {
	registry := NewRegistry(URLs{Server: "https://aggregator.example"})
	mux := http.NewServeMux()
	registry.RegisterPublicHandlers(mux)
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/internal/deployment-functions/fetch", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("public listener exposed internal endpoint: status = %d", recorder.Code)
	}
}

func TestInternalBundleEndpoint(t *testing.T) {
	registry := NewRegistry(URLs{Server: "https://aggregator.example"})
	profile := fetchProfile()
	definition := fetchDeployment("fetch-profiled", true)
	if err := registry.Set([]Profile{profile}, []DeploymentFunction{definition}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	mux := http.NewServeMux()
	registry.RegisterInternalHandlers(mux)
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/internal/deployment-functions/fetch-profiled", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var bundle Bundle
	if err := json.Unmarshal(recorder.Body.Bytes(), &bundle); err != nil {
		t.Fatalf("decode bundle: %v", err)
	}
	if bundle.Profile == nil || bundle.Profile.Name != "fetch" {
		t.Fatalf("unexpected profile: %#v", bundle.Profile)
	}
	if bundle.APIVersion != BundleAPIVersion || bundle.Kind != BundleKind {
		t.Fatalf("unexpected bundle envelope: %s %s", bundle.APIVersion, bundle.Kind)
	}
	etag := recorder.Header().Get("ETag")
	if etag == "" {
		t.Fatal("bundle response has no ETag")
	}
	conditional := httptest.NewRequest(http.MethodGet, "/internal/deployment-functions/fetch-profiled", nil)
	conditional.Header.Set("If-None-Match", etag)
	recorder = httptest.NewRecorder()
	mux.ServeHTTP(recorder, conditional)
	if recorder.Code != http.StatusNotModified {
		t.Fatalf("conditional status = %d", recorder.Code)
	}
}

func TestValidationRejectsMissingDistributionBinding(t *testing.T) {
	profile := fetchProfile()
	definition := fetchDeployment("fetch-profiled", true)
	definition.Spec.Orchestration.RouteBindings.Distributions = nil
	err := ValidateBundle(&Bundle{DeploymentFunction: definition, Profile: &profile})
	if err == nil || !strings.Contains(err.Error(), "missing route binding") {
		t.Fatalf("expected missing binding error, got %v", err)
	}
}

func ptr[T any](value T) *T { return &value }

func assertValidTurtle(t *testing.T, body string) {
	t.Helper()
	stream, errors := rdfgo.Parse(strings.NewReader(body), rdfgo.ParserOptions{Format: "text/turtle"})
	store := rdfgo.NewStore()
	store.Import(stream)
	for err := range errors {
		if err != nil {
			t.Fatalf("invalid Turtle: %v\n%s", err, body)
		}
	}
}
