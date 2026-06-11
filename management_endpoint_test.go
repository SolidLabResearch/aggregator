package main

import (
	"aggregator/auth"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newManagementTestMux() *http.ServeMux {
	mux := http.NewServeMux()
	data := &ConfigurationData{
		actors:               make(map[string]Actor),
		pendingAuthorization: make(map[string]pendingAuthorizationCodeFlow),
		serveMux:             mux,
	}
	mux.HandleFunc("/registration", data.HandleManagementEndpoint)
	return mux
}

func bypassAuth(t *testing.T) {
	t.Helper()
	oldAuthorizeRequest := authorizeRequest
	oldCreateAuthResource := createAuthResource
	oldDeleteAuthResource := deleteAuthResource

	authorizeRequest = func(http.ResponseWriter, *http.Request, []auth.Permission) bool {
		return true
	}
	createAuthResource = func(string, []auth.ResourceScope, interface{}) error {
		return nil
	}
	deleteAuthResource = func(string) {}

	t.Cleanup(func() {
		authorizeRequest = oldAuthorizeRequest
		createAuthResource = oldCreateAuthResource
		deleteAuthResource = oldDeleteAuthResource
	})
}

func waitForCondition(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition was not met before timeout")
}

func TestManagementEndpointCreatesListsAndDeletesAggregator(t *testing.T) {
	bypassAuth(t)
	mux := newManagementTestMux()

	createRequest := httptest.NewRequest(
		http.MethodPost,
		"http://aggregator.example/registration",
		strings.NewReader(`{"management_flow":"none"}`),
	)
	createRequest.Header.Set("Content-Type", "application/json")
	createResponse := httptest.NewRecorder()

	mux.ServeHTTP(createResponse, createRequest)

	if createResponse.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d: %s", http.StatusCreated, createResponse.Code, createResponse.Body.String())
	}

	var created map[string]string
	if err := json.Unmarshal(createResponse.Body.Bytes(), &created); err != nil {
		t.Fatalf("create response body is not JSON: %v", err)
	}
	aggregator := created["aggregator"]
	if !strings.HasPrefix(aggregator, "http://aggregator.example/") || !strings.HasSuffix(aggregator, "/") {
		t.Fatalf("unexpected aggregator URL: %q", aggregator)
	}

	listRequest := httptest.NewRequest(http.MethodGet, "http://aggregator.example/registration", nil)
	listResponse := httptest.NewRecorder()

	mux.ServeHTTP(listResponse, listRequest)

	if listResponse.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, listResponse.Code)
	}
	var aggregators []string
	if err := json.Unmarshal(listResponse.Body.Bytes(), &aggregators); err != nil {
		t.Fatalf("list response body is not JSON array: %v", err)
	}
	if len(aggregators) != 1 || aggregators[0] != aggregator {
		t.Fatalf("expected listed aggregators to contain %q, got %#v", aggregator, aggregators)
	}

	deleteRequest := httptest.NewRequest(
		http.MethodDelete,
		"http://aggregator.example/registration",
		strings.NewReader(`{"aggregator":"`+aggregator+`"}`),
	)
	deleteRequest.Header.Set("Content-Type", "application/json")
	deleteResponse := httptest.NewRecorder()

	mux.ServeHTTP(deleteResponse, deleteRequest)

	if deleteResponse.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d: %s", http.StatusNoContent, deleteResponse.Code, deleteResponse.Body.String())
	}
}

func unsignedJWT(payload map[string]string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payloadBytes, _ := json.Marshal(payload)
	return header + "." + base64.RawURLEncoding.EncodeToString(payloadBytes) + "."
}

func TestManagementEndpointAuthorizationCodeStartReturnsPKCEParameters(t *testing.T) {
	bypassAuth(t)
	oldIssuer := auth.AS_ISSUER
	t.Cleanup(func() {
		auth.AS_ISSUER = oldIssuer
	})
	mux := newManagementTestMux()

	createRequest := httptest.NewRequest(
		http.MethodPost,
		"http://aggregator.example/registration",
		strings.NewReader(`{"management_flow":"authorization_code","authorization_server":"http://localhost:4581"}`),
	)
	createRequest.Header.Set("Content-Type", "application/json")
	createRequest.Header.Set("Authorization", "Bearer "+unsignedJWT(map[string]string{
		"iss": "http://idp.example",
		"aud": "http://app.example/client.jsonld",
	}))
	createResponse := httptest.NewRecorder()

	mux.ServeHTTP(createResponse, createRequest)

	if createResponse.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d: %s", http.StatusCreated, createResponse.Code, createResponse.Body.String())
	}
	var started map[string]string
	if err := json.Unmarshal(createResponse.Body.Bytes(), &started); err != nil {
		t.Fatalf("start response body is not JSON: %v", err)
	}
	for _, field := range []string{"aggregator_client_id", "code_challenge", "code_challenge_method", "state"} {
		if started[field] == "" {
			t.Fatalf("expected start response to include %s: %#v", field, started)
		}
	}
	if started["aggregator"] != "" {
		t.Fatalf("authorization_code start must not create an aggregator: %#v", started)
	}
	if started["code_challenge_method"] != "S256" {
		t.Fatalf("expected S256 challenge method, got %q", started["code_challenge_method"])
	}
	if auth.AS_ISSUER == "http://localhost:4581" {
		t.Fatalf("start request should not update AS issuer before finish")
	}
}

func TestManagementEndpointAuthorizationCodeFinishCreatesAggregator(t *testing.T) {
	bypassAuth(t)
	oldIssuer := auth.AS_ISSUER
	oldRedeem := redeemAuthorizationCode
	oldValidate := validateClientRedirectURI
	t.Cleanup(func() {
		auth.AS_ISSUER = oldIssuer
		redeemAuthorizationCode = oldRedeem
		validateClientRedirectURI = oldValidate
	})
	validateClientRedirectURI = func(clientID, redirectURI string) error {
		if clientID != "http://app.example/client.jsonld" || redirectURI != "http://app.example/callback" {
			t.Fatalf("unexpected redirect validation input: client_id=%q redirect_uri=%q", clientID, redirectURI)
		}
		return nil
	}
	redeemAuthorizationCode = func(issuer, code, redirectURI, clientID, codeVerifier string) (tokenSet, error) {
		if issuer != "http://idp.example" || code != "code-1" || redirectURI != "http://app.example/callback" {
			t.Fatalf("unexpected token redemption input: issuer=%q code=%q redirect=%q", issuer, code, redirectURI)
		}
		if clientID != "http://aggregator.example/client.jsonld" || codeVerifier == "" {
			t.Fatalf("unexpected client_id/code_verifier: %q %q", clientID, codeVerifier)
		}
		return tokenSet{AccessToken: "aggregator-token", TokenType: "Bearer"}, nil
	}
	mux := newManagementTestMux()

	startRequest := httptest.NewRequest(
		http.MethodPost,
		"http://aggregator.example/registration",
		strings.NewReader(`{"management_flow":"authorization_code","authorization_server":"http://localhost:4581"}`),
	)
	startRequest.Header.Set("Content-Type", "application/json")
	startRequest.Header.Set("Authorization", "Bearer "+unsignedJWT(map[string]string{
		"iss": "http://idp.example",
		"aud": "http://app.example/client.jsonld",
	}))
	startResponse := httptest.NewRecorder()
	mux.ServeHTTP(startResponse, startRequest)
	if startResponse.Code != http.StatusCreated {
		t.Fatalf("expected start status %d, got %d: %s", http.StatusCreated, startResponse.Code, startResponse.Body.String())
	}

	var started map[string]string
	if err := json.Unmarshal(startResponse.Body.Bytes(), &started); err != nil {
		t.Fatalf("start response body is not JSON: %v", err)
	}
	finishRequest := httptest.NewRequest(
		http.MethodPost,
		"http://aggregator.example/registration",
		strings.NewReader(`{"management_flow":"authorization_code","code":"code-1","redirect_uri":"http://app.example/callback","state":"`+started["state"]+`"}`),
	)
	finishRequest.Header.Set("Content-Type", "application/json")
	finishRequest.Header.Set("Authorization", "Bearer "+unsignedJWT(map[string]string{
		"iss": "http://idp.example",
		"aud": "http://app.example/client.jsonld",
	}))
	finishResponse := httptest.NewRecorder()
	mux.ServeHTTP(finishResponse, finishRequest)

	if finishResponse.Code != http.StatusCreated {
		t.Fatalf("expected finish status %d, got %d: %s", http.StatusCreated, finishResponse.Code, finishResponse.Body.String())
	}
	var finished map[string]string
	if err := json.Unmarshal(finishResponse.Body.Bytes(), &finished); err != nil {
		t.Fatalf("finish response body is not JSON: %v", err)
	}
	if finished["aggregator"] == "" {
		t.Fatalf("finish response must include aggregator: %#v", finished)
	}
	if auth.AS_ISSUER != "http://localhost:4581" {
		t.Fatalf("expected AS issuer to be updated on finish, got %q", auth.AS_ISSUER)
	}
}

func TestManagementEndpointDeleteRemovesAggregatorAuthResources(t *testing.T) {
	bypassAuth(t)
	oldValidate := validateClientRedirectURI
	oldRedeem := redeemAuthorizationCode
	oldDelete := deleteAuthResource
	t.Cleanup(func() {
		validateClientRedirectURI = oldValidate
		redeemAuthorizationCode = oldRedeem
		deleteAuthResource = oldDelete
	})
	validateClientRedirectURI = func(string, string) error { return nil }
	redeemAuthorizationCode = func(string, string, string, string, string) (tokenSet, error) {
		return tokenSet{AccessToken: "aggregator-token"}, nil
	}
	deleted := map[string]int{}
	deleteAuthResource = func(resource string) {
		deleted[resource]++
	}
	mux := newManagementTestMux()

	startRequest := httptest.NewRequest(
		http.MethodPost,
		"http://aggregator.example/registration",
		strings.NewReader(`{"management_flow":"authorization_code","authorization_server":"http://localhost:4581"}`),
	)
	startRequest.Header.Set("Content-Type", "application/json")
	startRequest.Header.Set("Authorization", "Bearer "+unsignedJWT(map[string]string{
		"iss": "http://idp.example",
		"aud": "http://app.example/client.jsonld",
	}))
	startResponse := httptest.NewRecorder()
	mux.ServeHTTP(startResponse, startRequest)
	var started map[string]string
	if err := json.Unmarshal(startResponse.Body.Bytes(), &started); err != nil {
		t.Fatalf("start response body is not JSON: %v", err)
	}

	finishRequest := httptest.NewRequest(
		http.MethodPost,
		"http://aggregator.example/registration",
		strings.NewReader(`{"management_flow":"authorization_code","code":"code-1","redirect_uri":"http://app.example/callback","state":"`+started["state"]+`"}`),
	)
	finishRequest.Header.Set("Content-Type", "application/json")
	finishRequest.Header.Set("Authorization", "Bearer "+unsignedJWT(map[string]string{
		"iss": "http://idp.example",
		"aud": "http://app.example/client.jsonld",
	}))
	finishResponse := httptest.NewRecorder()
	mux.ServeHTTP(finishResponse, finishRequest)
	var finished map[string]string
	if err := json.Unmarshal(finishResponse.Body.Bytes(), &finished); err != nil {
		t.Fatalf("finish response body is not JSON: %v", err)
	}
	aggregator := finished["aggregator"]

	serviceRequestBody := `@prefix aggr: <https://w3id.org/aggregator#> .

<> a aggr:Service ;
    aggr:performs <http://aggregator.example/transformations#SPARQLEvaluation> .
`
	deployRequest := httptest.NewRequest(http.MethodPost, aggregator+"services", strings.NewReader(serviceRequestBody))
	deployRequest.Header.Set("Content-Type", "text/turtle")
	deployResponse := httptest.NewRecorder()
	mux.ServeHTTP(deployResponse, deployRequest)
	serviceURL := deployResponse.Header().Get("Location")
	if serviceURL == "" {
		t.Fatalf("expected service Location, got status %d body %s", deployResponse.Code, deployResponse.Body.String())
	}

	deleteRequest := httptest.NewRequest(
		http.MethodDelete,
		"http://aggregator.example/registration",
		strings.NewReader(`{"aggregator":"`+aggregator+`"}`),
	)
	deleteRequest.Header.Set("Content-Type", "application/json")
	deleteResponse := httptest.NewRecorder()
	mux.ServeHTTP(deleteResponse, deleteRequest)
	if deleteResponse.Code != http.StatusNoContent {
		t.Fatalf("expected delete status %d, got %d: %s", http.StatusNoContent, deleteResponse.Code, deleteResponse.Body.String())
	}

	for _, resource := range []string{
		serviceURL,
		strings.TrimSuffix(serviceURL, "/"),
		serviceURL + "output",
		aggregator,
		strings.TrimSuffix(aggregator, "/"),
		aggregator + "transformations",
		aggregator + "services",
	} {
		if deleted[resource] == 0 {
			t.Fatalf("expected auth resource %q to be deleted, got %#v", resource, deleted)
		}
	}
}

func TestManagementEndpointAuthorizationCodeRequiresTokenAndAS(t *testing.T) {
	bypassAuth(t)
	mux := newManagementTestMux()

	missingTokenRequest := httptest.NewRequest(
		http.MethodPost,
		"http://aggregator.example/registration",
		strings.NewReader(`{"management_flow":"authorization_code","authorization_server":"http://localhost:4581"}`),
	)
	missingTokenRequest.Header.Set("Content-Type", "application/json")
	missingTokenResponse := httptest.NewRecorder()
	mux.ServeHTTP(missingTokenResponse, missingTokenRequest)
	if missingTokenResponse.Code != http.StatusUnauthorized {
		t.Fatalf("expected missing token status %d, got %d", http.StatusUnauthorized, missingTokenResponse.Code)
	}

	missingASRequest := httptest.NewRequest(
		http.MethodPost,
		"http://aggregator.example/registration",
		strings.NewReader(`{"management_flow":"authorization_code"}`),
	)
	missingASRequest.Header.Set("Content-Type", "application/json")
	missingASRequest.Header.Set("Authorization", "Bearer oidc-token")
	missingASResponse := httptest.NewRecorder()
	mux.ServeHTTP(missingASResponse, missingASRequest)
	if missingASResponse.Code != http.StatusBadRequest {
		t.Fatalf("expected missing authorization_server status %d, got %d", http.StatusBadRequest, missingASResponse.Code)
	}
}

func TestAggregatorDescriptionAndCollections(t *testing.T) {
	bypassAuth(t)
	mux := newManagementTestMux()

	createRequest := httptest.NewRequest(
		http.MethodPost,
		"http://aggregator.example/registration",
		strings.NewReader(`{"management_flow":"none"}`),
	)
	createRequest.Header.Set("Content-Type", "application/json")
	createResponse := httptest.NewRecorder()
	mux.ServeHTTP(createResponse, createRequest)

	var created map[string]string
	if err := json.Unmarshal(createResponse.Body.Bytes(), &created); err != nil {
		t.Fatalf("create response body is not JSON: %v", err)
	}
	aggregator := created["aggregator"]

	descriptionRequest := httptest.NewRequest(http.MethodGet, aggregator, nil)
	descriptionResponse := httptest.NewRecorder()
	mux.ServeHTTP(descriptionResponse, descriptionRequest)

	if descriptionResponse.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, descriptionResponse.Code)
	}
	var description map[string]interface{}
	if err := json.Unmarshal(descriptionResponse.Body.Bytes(), &description); err != nil {
		t.Fatalf("description response body is not JSON: %v", err)
	}
	if description["@type"] != "aggr:Aggregator" {
		t.Fatalf("expected aggr:Aggregator type, got %#v", description["@type"])
	}
	if description["transformation_catalog"] != aggregator+"transformations" {
		t.Fatalf("unexpected transformation_catalog: %#v", description["transformation_catalog"])
	}
	if description["service_collection_endpoint"] != aggregator+"services" {
		t.Fatalf("unexpected service_collection_endpoint: %#v", description["service_collection_endpoint"])
	}
	if _, ok := description["created_at"].(string); !ok {
		t.Fatalf("created_at must be present as a string, got %#v", description["created_at"])
	}
	if description["login_status"] != true {
		t.Fatalf("expected login_status true, got %#v", description["login_status"])
	}

	catalogRequest := httptest.NewRequest(http.MethodGet, aggregator+"transformations", nil)
	catalogResponse := httptest.NewRecorder()
	mux.ServeHTTP(catalogResponse, catalogRequest)
	if catalogResponse.Code != http.StatusOK || !strings.Contains(catalogResponse.Body.String(), "a aggr:TransformationCatalog") {
		t.Fatalf("unexpected transformation catalog response: %d %s", catalogResponse.Code, catalogResponse.Body.String())
	}

	servicesRequest := httptest.NewRequest(http.MethodGet, aggregator+"services", nil)
	servicesResponse := httptest.NewRecorder()
	mux.ServeHTTP(servicesResponse, servicesRequest)
	if servicesResponse.Code != http.StatusOK || !strings.Contains(servicesResponse.Body.String(), "a aggr:ServiceCollection") {
		t.Fatalf("unexpected service collection response: %d %s", servicesResponse.Code, servicesResponse.Body.String())
	}
	if !strings.Contains(servicesResponse.Body.String(), "<"+aggregator+"services>\n    a aggr:ServiceCollection") {
		t.Fatalf("service collection must identify the advertised collection URL:\n%s", servicesResponse.Body.String())
	}
	if servicesResponse.Header().Get("ETag") == "" {
		t.Fatalf("service collection response must include an ETag")
	}
}

func TestServiceDeploymentDescriptionCollectionAndDeletion(t *testing.T) {
	bypassAuth(t)
	mux := newManagementTestMux()

	createRequest := httptest.NewRequest(
		http.MethodPost,
		"http://aggregator.example/registration",
		strings.NewReader(`{"management_flow":"none"}`),
	)
	createRequest.Header.Set("Content-Type", "application/json")
	createResponse := httptest.NewRecorder()
	mux.ServeHTTP(createResponse, createRequest)

	var created map[string]string
	if err := json.Unmarshal(createResponse.Body.Bytes(), &created); err != nil {
		t.Fatalf("create response body is not JSON: %v", err)
	}
	aggregator := created["aggregator"]

	serviceRequestBody := `@prefix aggr: <https://w3id.org/aggregator#> .

<> a aggr:Service ;
    aggr:performs <http://aggregator.example/transformations#SPARQLEvaluation> .
`
	deployRequest := httptest.NewRequest(http.MethodPost, aggregator+"services", strings.NewReader(serviceRequestBody))
	deployRequest.Header.Set("Content-Type", "text/turtle")
	deployResponse := httptest.NewRecorder()
	mux.ServeHTTP(deployResponse, deployRequest)

	if deployResponse.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d: %s", http.StatusCreated, deployResponse.Code, deployResponse.Body.String())
	}
	serviceURL := deployResponse.Header().Get("Location")
	if !strings.HasPrefix(serviceURL, aggregator+"services/") {
		t.Fatalf("unexpected service Location: %q", serviceURL)
	}
	serviceDescription := deployResponse.Body.String()
	for _, snippet := range []string{
		"a aggr:Service",
		"a dcat:DataService",
		"a prov:SoftwareAgent",
		"aggr:performs <http://aggregator.example/transformations#SPARQLEvaluation>",
		"dcat:servesDataset",
		"dcat:accessURL <" + serviceURL + "output>",
	} {
		if !strings.Contains(serviceDescription, snippet) {
			t.Fatalf("service description missing %q:\n%s", snippet, serviceDescription)
		}
	}

	collectionRequest := httptest.NewRequest(http.MethodGet, aggregator+"services", nil)
	collectionResponse := httptest.NewRecorder()
	mux.ServeHTTP(collectionResponse, collectionRequest)
	if !strings.Contains(collectionResponse.Body.String(), "<"+aggregator+"services>\n    a aggr:ServiceCollection") {
		t.Fatalf("service collection must identify the advertised collection URL:\n%s", collectionResponse.Body.String())
	}
	if !strings.Contains(collectionResponse.Body.String(), "aggr:hasService <"+serviceURL+">") {
		t.Fatalf("service collection does not advertise service %q:\n%s", serviceURL, collectionResponse.Body.String())
	}

	catalogRequest := httptest.NewRequest(http.MethodGet, aggregator+"transformations", nil)
	catalogResponse := httptest.NewRecorder()
	mux.ServeHTTP(catalogResponse, catalogRequest)
	if !strings.Contains(catalogResponse.Body.String(), "aggr:implementedBy <"+serviceURL+">") {
		t.Fatalf("transformation catalog does not include service %q:\n%s", serviceURL, catalogResponse.Body.String())
	}

	outputHeadRequest := httptest.NewRequest(http.MethodHead, serviceURL+"output", nil)
	outputHeadResponse := httptest.NewRecorder()
	mux.ServeHTTP(outputHeadResponse, outputHeadRequest)
	if outputHeadResponse.Code >= http.StatusInternalServerError {
		t.Fatalf("output HEAD must not return 5xx, got %d", outputHeadResponse.Code)
	}

	outputRequest := httptest.NewRequest(http.MethodGet, serviceURL+"output", nil)
	outputResponse := httptest.NewRecorder()
	mux.ServeHTTP(outputResponse, outputRequest)
	if outputResponse.Header().Get("Link") != "<"+serviceURL+">; rel=\"https://w3id.org/aggregator#fromService\"" {
		t.Fatalf("unexpected output Link header: %q", outputResponse.Header().Get("Link"))
	}

	deleteRequest := httptest.NewRequest(http.MethodDelete, serviceURL, nil)
	deleteResponse := httptest.NewRecorder()
	mux.ServeHTTP(deleteResponse, deleteRequest)
	if deleteResponse.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, deleteResponse.Code)
	}

	getDeletedRequest := httptest.NewRequest(http.MethodGet, serviceURL, nil)
	getDeletedResponse := httptest.NewRecorder()
	mux.ServeHTTP(getDeletedResponse, getDeletedRequest)
	if getDeletedResponse.Code != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d", http.StatusNotFound, getDeletedResponse.Code)
	}
}

func TestCopyResourceServiceCopiesInputResourceToOutput(t *testing.T) {
	bypassAuth(t)
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		upstreamHits.Add(1)
		if request.Method != http.MethodGet {
			t.Errorf("expected CopyResource cache fill to use GET, got %s", request.Method)
		}
		response.Header().Set("Content-Type", "text/plain")
		_, _ = response.Write([]byte("copied payload"))
	}))
	defer upstream.Close()
	mux := newManagementTestMux()

	createRequest := httptest.NewRequest(
		http.MethodPost,
		"http://aggregator.example/registration",
		strings.NewReader(`{"management_flow":"none"}`),
	)
	createRequest.Header.Set("Content-Type", "application/json")
	createResponse := httptest.NewRecorder()
	mux.ServeHTTP(createResponse, createRequest)

	var created map[string]string
	if err := json.Unmarshal(createResponse.Body.Bytes(), &created); err != nil {
		t.Fatalf("create response body is not JSON: %v", err)
	}
	aggregator := created["aggregator"]

	serviceRequestBody := `@prefix aggr: <https://w3id.org/aggregator#> .
@prefix fno: <https://w3id.org/function/ontology#> .
@prefix fnoc: <https://w3id.org/function/vocabulary/composition#> .

<> a aggr:Service ;
    aggr:performs <http://localhost:5000/transformations#CopyResource> ;
    aggr:applies [
        a fno:AppliedFunction ;
        fnoc:applies <http://localhost:5000/transformations#CopyResource> ;
        fnoc:parameterBindings (
            [
                fnoc:boundParameter <http://localhost:5000/transformations#ResourceLocation> ;
                fnoc:boundToTerm <` + upstream.URL + `/data>
            ]
        )
    ] .
`
	deployRequest := httptest.NewRequest(http.MethodPost, aggregator+"services", strings.NewReader(serviceRequestBody))
	deployRequest.Header.Set("Content-Type", "text/turtle")
	deployResponse := httptest.NewRecorder()
	mux.ServeHTTP(deployResponse, deployRequest)
	if deployResponse.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d: %s", http.StatusCreated, deployResponse.Code, deployResponse.Body.String())
	}
	waitForCondition(t, func() bool { return upstreamHits.Load() == 1 })
	serviceURL := deployResponse.Header().Get("Location")
	if serviceURL == "" {
		t.Fatal("expected service Location")
	}
	if !strings.Contains(deployResponse.Body.String(), "<resourceLocation> <"+upstream.URL+"/data>") {
		t.Fatalf("service description does not include resource input:\n%s", deployResponse.Body.String())
	}

	outputRequest := httptest.NewRequest(http.MethodGet, serviceURL+"output", nil)
	outputResponse := httptest.NewRecorder()
	waitForCondition(t, func() bool {
		outputResponse = httptest.NewRecorder()
		mux.ServeHTTP(outputResponse, outputRequest)
		return outputResponse.Code == http.StatusOK
	})
	if strings.TrimSpace(outputResponse.Body.String()) != "copied payload" {
		t.Fatalf("unexpected copied output: %q", outputResponse.Body.String())
	}
	if outputResponse.Header().Get("Content-Type") != "text/plain" {
		t.Fatalf("unexpected copied content type: %q", outputResponse.Header().Get("Content-Type"))
	}
	if upstreamHits.Load() != 1 {
		t.Fatalf("expected output GET to use cached CopyResource output, got %d upstream requests", upstreamHits.Load())
	}

	outputHeadRequest := httptest.NewRequest(http.MethodHead, serviceURL+"output", nil)
	outputHeadResponse := httptest.NewRecorder()
	mux.ServeHTTP(outputHeadResponse, outputHeadRequest)
	if outputHeadResponse.Code != http.StatusOK {
		t.Fatalf("expected HEAD output status %d, got %d: %s", http.StatusOK, outputHeadResponse.Code, outputHeadResponse.Body.String())
	}
	expectedLink := "<" + serviceURL + ">; rel=\"https://w3id.org/aggregator#fromService\""
	if outputHeadResponse.Header().Get("Link") != expectedLink {
		t.Fatalf("unexpected HEAD output Link header: %q", outputHeadResponse.Header().Get("Link"))
	}
	if outputHeadResponse.Body.Len() != 0 {
		t.Fatalf("HEAD output must not include a response body, got %q", outputHeadResponse.Body.String())
	}
	if upstreamHits.Load() != 1 {
		t.Fatalf("expected output HEAD to use cached CopyResource output, got %d upstream requests", upstreamHits.Load())
	}
}

func TestCopyResourceServiceAcceptsFullIRIsInServiceRequest(t *testing.T) {
	bypassAuth(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "text/plain")
		_, _ = response.Write([]byte("full iri payload"))
	}))
	defer upstream.Close()
	mux := newManagementTestMux()

	createRequest := httptest.NewRequest(
		http.MethodPost,
		"http://aggregator.example/registration",
		strings.NewReader(`{"management_flow":"none"}`),
	)
	createRequest.Header.Set("Content-Type", "application/json")
	createResponse := httptest.NewRecorder()
	mux.ServeHTTP(createResponse, createRequest)

	var created map[string]string
	if err := json.Unmarshal(createResponse.Body.Bytes(), &created); err != nil {
		t.Fatalf("create response body is not JSON: %v", err)
	}
	aggregator := created["aggregator"]

	serviceRequestBody := `
[] a <https://w3id.org/aggregator#Service> ;
    <https://w3id.org/aggregator#performs> <http://localhost:5000/transformations#CopyResource> ;
    <https://w3id.org/aggregator#applies> [
        a <https://w3id.org/function/ontology#AppliedFunction> ;
        <https://w3id.org/function/vocabulary/composition#applies> <http://localhost:5000/transformations#CopyResource> ;
        <https://w3id.org/function/vocabulary/composition#parameterBindings> (
            [
                <https://w3id.org/function/vocabulary/composition#boundParameter> <http://localhost:5000/transformations#ResourceLocation> ;
                <https://w3id.org/function/vocabulary/composition#boundToTerm> <` + upstream.URL + `/data>
            ]
        )
    ] .
`
	deployRequest := httptest.NewRequest(http.MethodPost, aggregator+"services", strings.NewReader(serviceRequestBody))
	deployRequest.Header.Set("Content-Type", "text/turtle")
	deployResponse := httptest.NewRecorder()
	mux.ServeHTTP(deployResponse, deployRequest)
	if deployResponse.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d: %s", http.StatusCreated, deployResponse.Code, deployResponse.Body.String())
	}
	serviceURL := deployResponse.Header().Get("Location")
	if serviceURL == "" {
		t.Fatal("expected service Location")
	}

	collectionRequest := httptest.NewRequest(http.MethodGet, aggregator+"services", nil)
	collectionResponse := httptest.NewRecorder()
	mux.ServeHTTP(collectionResponse, collectionRequest)
	if !strings.Contains(collectionResponse.Body.String(), "aggr:hasService <"+serviceURL+">") {
		t.Fatalf("service collection does not advertise service %q:\n%s", serviceURL, collectionResponse.Body.String())
	}

	outputHeadRequest := httptest.NewRequest(http.MethodHead, serviceURL+"output", nil)
	outputHeadResponse := httptest.NewRecorder()
	waitForCondition(t, func() bool {
		outputHeadResponse = httptest.NewRecorder()
		mux.ServeHTTP(outputHeadResponse, outputHeadRequest)
		return outputHeadResponse.Code == http.StatusOK
	})
}

func TestCopyResourceOutputReturnsServiceUnavailableWhileFetchIsRunning(t *testing.T) {
	bypassAuth(t)
	fetchStarted := make(chan struct{}, 1)
	releaseFetch := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		fetchStarted <- struct{}{}
		<-releaseFetch
		response.Header().Set("Content-Type", "text/plain")
		_, _ = response.Write([]byte("copied after startup"))
	}))
	defer upstream.Close()
	mux := newManagementTestMux()

	createRequest := httptest.NewRequest(
		http.MethodPost,
		"http://aggregator.example/registration",
		strings.NewReader(`{"management_flow":"none"}`),
	)
	createRequest.Header.Set("Content-Type", "application/json")
	createResponse := httptest.NewRecorder()
	mux.ServeHTTP(createResponse, createRequest)

	var created map[string]string
	if err := json.Unmarshal(createResponse.Body.Bytes(), &created); err != nil {
		t.Fatalf("create response body is not JSON: %v", err)
	}
	aggregator := created["aggregator"]

	serviceRequestBody := `@prefix aggr: <https://w3id.org/aggregator#> .
@prefix fno: <https://w3id.org/function/ontology#> .
@prefix fnoc: <https://w3id.org/function/vocabulary/composition#> .

<> a aggr:Service ;
    aggr:performs <http://localhost:5000/transformations#CopyResource> ;
    aggr:applies [
        a fno:AppliedFunction ;
        fnoc:applies <http://localhost:5000/transformations#CopyResource> ;
        fnoc:parameterBindings (
            [
                fnoc:boundParameter <http://localhost:5000/transformations#ResourceLocation> ;
                fnoc:boundToTerm <` + upstream.URL + `/not-ready>
            ]
        )
    ] .
`
	deployRequest := httptest.NewRequest(http.MethodPost, aggregator+"services", strings.NewReader(serviceRequestBody))
	deployRequest.Header.Set("Content-Type", "text/turtle")
	deployResponse := httptest.NewRecorder()
	mux.ServeHTTP(deployResponse, deployRequest)
	if deployResponse.Code != http.StatusCreated {
		t.Fatalf("expected deploy status %d, got %d: %s", http.StatusCreated, deployResponse.Code, deployResponse.Body.String())
	}
	serviceURL := deployResponse.Header().Get("Location")
	select {
	case <-fetchStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("expected CopyResource fetch to start after deployment")
	}

	outputRequest := httptest.NewRequest(http.MethodGet, serviceURL+"output", nil)
	outputResponse := httptest.NewRecorder()
	mux.ServeHTTP(outputResponse, outputRequest)
	if outputResponse.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected output status %d, got %d: %s", http.StatusServiceUnavailable, outputResponse.Code, outputResponse.Body.String())
	}
	if !strings.Contains(outputResponse.Body.String(), "not ready yet") {
		t.Fatalf("expected readiness message, got %q", outputResponse.Body.String())
	}
	if outputResponse.Header().Get("Retry-After") == "" {
		t.Fatal("expected Retry-After header")
	}

	outputHeadRequest := httptest.NewRequest(http.MethodHead, serviceURL+"output", nil)
	outputHeadResponse := httptest.NewRecorder()
	mux.ServeHTTP(outputHeadResponse, outputHeadRequest)
	if outputHeadResponse.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected HEAD output status %d, got %d", http.StatusServiceUnavailable, outputHeadResponse.Code)
	}
	if outputHeadResponse.Body.Len() != 0 {
		t.Fatalf("HEAD output must not include a response body, got %q", outputHeadResponse.Body.String())
	}

	close(releaseFetch)
	waitForCondition(t, func() bool {
		readyRequest := httptest.NewRequest(http.MethodGet, serviceURL+"output", nil)
		readyResponse := httptest.NewRecorder()
		mux.ServeHTTP(readyResponse, readyRequest)
		return readyResponse.Code == http.StatusOK && strings.TrimSpace(readyResponse.Body.String()) == "copied after startup"
	})
}

func TestCopyResourceOutputReplaysUpstreamNotFound(t *testing.T) {
	bypassAuth(t)
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		http.NotFound(response, nil)
	}))
	defer upstream.Close()
	mux := newManagementTestMux()

	createRequest := httptest.NewRequest(
		http.MethodPost,
		"http://aggregator.example/registration",
		strings.NewReader(`{"management_flow":"none"}`),
	)
	createRequest.Header.Set("Content-Type", "application/json")
	createResponse := httptest.NewRecorder()
	mux.ServeHTTP(createResponse, createRequest)

	var created map[string]string
	if err := json.Unmarshal(createResponse.Body.Bytes(), &created); err != nil {
		t.Fatalf("create response body is not JSON: %v", err)
	}
	aggregator := created["aggregator"]

	serviceRequestBody := `@prefix aggr: <https://w3id.org/aggregator#> .
@prefix fno: <https://w3id.org/function/ontology#> .
@prefix fnoc: <https://w3id.org/function/vocabulary/composition#> .

<> a aggr:Service ;
    aggr:performs <http://localhost:5000/transformations#CopyResource> ;
    aggr:applies [
        a fno:AppliedFunction ;
        fnoc:applies <http://localhost:5000/transformations#CopyResource> ;
        fnoc:parameterBindings (
            [
                fnoc:boundParameter <http://localhost:5000/transformations#ResourceLocation> ;
                fnoc:boundToTerm <` + upstream.URL + `/missing>
            ]
        )
    ] .
`
	deployRequest := httptest.NewRequest(http.MethodPost, aggregator+"services", strings.NewReader(serviceRequestBody))
	deployRequest.Header.Set("Content-Type", "text/turtle")
	deployResponse := httptest.NewRecorder()
	mux.ServeHTTP(deployResponse, deployRequest)
	if deployResponse.Code != http.StatusCreated {
		t.Fatalf("expected deploy status %d, got %d: %s", http.StatusCreated, deployResponse.Code, deployResponse.Body.String())
	}
	waitForCondition(t, func() bool { return upstreamHits.Load() == 1 })
	serviceURL := deployResponse.Header().Get("Location")

	outputRequest := httptest.NewRequest(http.MethodGet, serviceURL+"output", nil)
	outputResponse := httptest.NewRecorder()
	mux.ServeHTTP(outputResponse, outputRequest)
	if outputResponse.Code != http.StatusNotFound {
		t.Fatalf("expected output status %d, got %d: %s", http.StatusNotFound, outputResponse.Code, outputResponse.Body.String())
	}
	if upstreamHits.Load() != 1 {
		t.Fatalf("expected copied 404 to be cached, got %d upstream requests", upstreamHits.Load())
	}
}

func TestManagementEndpointRejectsUnsupportedMediaType(t *testing.T) {
	bypassAuth(t)
	mux := newManagementTestMux()

	request := httptest.NewRequest(
		http.MethodPost,
		"http://aggregator.example/registration",
		strings.NewReader(`management_flow=none`),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()

	mux.ServeHTTP(response, request)

	if response.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("expected status %d, got %d", http.StatusUnsupportedMediaType, response.Code)
	}
}

func TestManagementEndpointRejectsInvalidFlow(t *testing.T) {
	bypassAuth(t)
	mux := newManagementTestMux()

	request := httptest.NewRequest(
		http.MethodPost,
		"http://aggregator.example/registration",
		strings.NewReader(`{"management_flow":"provision"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	mux.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, response.Code)
	}
}
