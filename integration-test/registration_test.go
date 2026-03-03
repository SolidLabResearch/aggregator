package integration_test

import (
	"aggregator-integration-test/mocks"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestRegistration_None_Create(t *testing.T) {
	aggregatorID := createAggregatorViaNone(t)
	defer deleteAggregator(t, aggregatorID, "")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	waitForDeploymentReady(t, ctx, map[string]string{
		"app.kubernetes.io/name":      "aggregator-instance",
		"agg.knows.idlab.ugent.be/id": aggregatorID,
	})

	baseURL := fmt.Sprintf("%s/%s", testEnv.AggregatorServerURL, aggregatorID)

	checkCtx, checkCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer checkCancel()

	attempt := 0
	for {
		select {
		case <-checkCtx.Done():
			t.Fatalf("Timed out waiting for none aggregator description: %v", checkCtx.Err())
		default:
			attempt++
			resp, err := http.Get(baseURL)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return
				}
			}
			time.Sleep(2 * time.Second)
		}
	}
}

func TestRegistration_None_DisablesUMAIngressAndEgress(t *testing.T) {
	aggregatorID := createAggregatorViaNone(t)
	defer deleteAggregator(t, aggregatorID, "")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	waitForDeploymentReady(t, ctx, map[string]string{
		"app.kubernetes.io/name":      "aggregator-instance",
		"agg.knows.idlab.ugent.be/id": aggregatorID,
	})

	egressUMAName := fmt.Sprintf("egress-uma-%s", aggregatorID)
	if _, err := testEnv.KubeClient.AppsV1().Deployments(testEnv.Namespace).Get(ctx, egressUMAName, metav1.GetOptions{}); err == nil {
		t.Fatal("Expected no egress-uma deployment for none registration type")
	} else if !apierrors.IsNotFound(err) {
		t.Fatalf("Failed to check egress-uma deployment: %v", err)
	}

	// Build FnO Turtle description
	source := "http://example.org"

	// Get transformation catalog from server description
	serverResp, err := http.Get(testEnv.AggregatorServerURL)
	if err != nil {
		t.Fatalf("Failed to fetch server description: %v", err)
	}
	defer serverResp.Body.Close()

	var serverDesc map[string]interface{}
	json.NewDecoder(serverResp.Body).Decode(&serverDesc)
	transformationsCatalog := serverDesc["transformation_catalog"].(string) + "#"

	baseURL := testEnv.AggregatorServerURL + "/" + aggregatorID + "/"

	turtleBody := fmt.Sprintf(`
		@prefix config: <%s> .
		@prefix agg: <%s> .
		@prefix fno: <https://w3id.org/function/ontology#> .
		@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
		@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .

		agg:test-service a fno:Execution ;
			fno:executes config:Fetch ;
			config:source "%s"^^xsd:string .
	`, transformationsCatalog, baseURL, source)

	servicesURL := fmt.Sprintf("%s/%s%s", testEnv.AggregatorServerURL, aggregatorID, testEnv.ServiceCollectionPath)
	req, err := http.NewRequest("POST", servicesURL, bytes.NewBuffer([]byte(turtleBody)))
	if err != nil {
		t.Fatalf("Failed to build service request: %v", err)
	}
	req.Header.Set("Content-Type", "text/turtle")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Service creation request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected 201 Created for service creation, got %d: %s", resp.StatusCode, string(bodyBytes))
	}

	serviceCtx, serviceCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer serviceCancel()

	deployment := waitForDeploymentExists(t, serviceCtx, map[string]string{
		"app.kubernetes.io/name":      "aggregator-service",
		"agg.knows.idlab.ugent.be/id": "test-service",
	})

	for _, env := range deployment.Spec.Template.Spec.Containers[0].Env {
		if env.Name == "HTTP_PROXY" || env.Name == "http_proxy" {
			t.Fatalf("Expected no HTTP proxy env for none registration type, found %s", env.Name)
		}
	}
}

func TestRegistration_None_DeleteWithoutAuth(t *testing.T) {
	aggregatorID := createAggregatorViaNone(t)
	deleted := false
	t.Cleanup(func() {
		if !deleted {
			deleteAggregator(t, aggregatorID, "")
		}
	})

	deleteBody := map[string]interface{}{
		"aggregator_id": aggregatorID,
	}
	deleteJSON, _ := json.Marshal(deleteBody)

	req, err := http.NewRequest("DELETE", testEnv.AggregatorServerURL+testEnv.RegistrationPath, bytes.NewBuffer(deleteJSON))
	if err != nil {
		t.Fatalf("Failed to create delete request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Delete request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected 204 No Content, got %d: %s", resp.StatusCode, string(bodyBytes))
	}

	deleted = true
}

func TestRegistration_AuthorizationCode_Start_Solid(t *testing.T) {
	oidcProvider, err := mocks.NewOIDCProvider(testEnv)
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}
	defer oidcProvider.Close()

	ownerWebID := "http://test.auth_start.solid/webid#me"
	oidcProvider.RegisterUser(ownerWebID, "auth-start-solid", "auth-start-solid-pass")
	authToken := createAuthToken(t, oidcProvider, ownerWebID, true)
	testClientId := oidcProvider.ClientMetadataURL([]string{"http://test.example/callback"})

	umaServer := mocks.NewUMAAuthorizationServer()
	defer umaServer.Close()

	reqBody := map[string]interface{}{
		"registration_type":    "authorization_code",
		"authorization_server": umaServer.URL(),
		"client_id":            testClientId,
	}
	body, _ := json.Marshal(reqBody)

	req, err := http.NewRequest("POST", testEnv.AggregatorServerURL+testEnv.RegistrationPath, bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected 201 Created, got %d: %s", resp.StatusCode, string(bodyBytes))
	}

	start := parseAuthCodeStartResponse(t, resp)

	if start.AggregatorClientID != testEnv.AggregatorServerURL+testEnv.ClientIDPath {
		t.Errorf("Expected aggregator_client_id %s, got %s", testEnv.AggregatorServerURL+testEnv.ClientIDPath, start.AggregatorClientID)
	}
	if start.CodeChallengeMethod != "S256" {
		t.Errorf("Expected code_challenge_method S256, got %s", start.CodeChallengeMethod)
	}

	t.Logf("Authorization code flow started: aggregator_client_id=%s, state=%s", start.AggregatorClientID, start.State)
}

func TestRegistration_AuthorizationCode_Finish_Solid(t *testing.T) {
	oidcProvider, err := mocks.NewOIDCProvider(testEnv)
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}
	defer oidcProvider.Close()

	ownerWebID := "http://test.auth_finish.solid/webid#me"
	oidcProvider.RegisterUser(ownerWebID, "auth-finish-solid", "auth-finish-solid-pass")
	authToken := createAuthToken(t, oidcProvider, ownerWebID, true)
	testClientId := oidcProvider.ClientMetadataURL([]string{"http://test.example/callback"})

	umaServer := mocks.NewUMAAuthorizationServer()
	defer umaServer.Close()

	reqBody := map[string]interface{}{
		"registration_type":    "authorization_code",
		"authorization_server": umaServer.URL(),
		"client_id":            testClientId,
	}
	body, _ := json.Marshal(reqBody)

	req, err := http.NewRequest("POST", testEnv.AggregatorServerURL+testEnv.RegistrationPath, bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Start request failed: %v", err)
	}
	defer resp.Body.Close()

	start := parseAuthCodeStartResponse(t, resp)
	state := start.State
	codeChallenge := start.CodeChallenge
	aggClientID := start.AggregatorClientID

	authReq, err := http.NewRequest("GET", oidcProvider.URL()+"/authorize", nil)
	if err != nil {
		t.Fatalf("Failed to create authorize request: %v", err)
	}

	q := authReq.URL.Query()
	q.Set("response_type", "code")
	q.Set("client_id", aggClientID)
	q.Set("redirect_uri", "http://test.example/callback")
	q.Set("scope", "openid webid offline_access")
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)
	authReq.URL.RawQuery = q.Encode()

	authClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	authResp, err := authClient.Do(authReq)
	if err != nil {
		t.Fatalf("Authorization request failed: %v", err)
	}
	defer authResp.Body.Close()

	if authResp.StatusCode != http.StatusFound {
		bodyBytes, _ := io.ReadAll(authResp.Body)
		t.Fatalf("Expected 302 redirect from authorize endpoint, got %d: %s", authResp.StatusCode, string(bodyBytes))
	}

	location := authResp.Header.Get("Location")
	if location == "" {
		t.Fatalf("No Location header in authorize response")
	}

	redirectURL, err := http.NewRequest("GET", location, nil)
	if err != nil {
		t.Fatalf("Failed to parse redirect URL: %v", err)
	}

	code := redirectURL.URL.Query().Get("code")
	if code == "" {
		t.Fatalf("No authorization code in redirect")
	}

	finishBody := map[string]interface{}{
		"registration_type": "authorization_code",
		"code":              code,
		"redirect_uri":      "http://test.example/callback",
		"state":             state,
	}
	finishJSON, _ := json.Marshal(finishBody)

	finishReq, err := http.NewRequest("POST", testEnv.AggregatorServerURL+testEnv.RegistrationPath, bytes.NewBuffer(finishJSON))
	if err != nil {
		t.Fatalf("Failed to create finish request: %v", err)
	}
	finishReq.Header.Set("Content-Type", "application/json")
	finishReq.Header.Set("Authorization", "Bearer "+authToken)

	finishResp, err := client.Do(finishReq)
	if err != nil {
		t.Fatalf("Finish request failed: %v", err)
	}
	defer finishResp.Body.Close()

	if finishResp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(finishResp.Body)
		t.Fatalf("Expected 201 Created on finish, got %d: %s", finishResp.StatusCode, string(bodyBytes))
	}

	var finishResponse map[string]interface{}
	if err := json.NewDecoder(finishResp.Body).Decode(&finishResponse); err != nil {
		t.Fatalf("Failed to decode finish response: %v", err)
	}

	aggregatorID, ok := finishResponse["aggregator_id"].(string)
	if !ok || aggregatorID == "" {
		t.Errorf("Response missing aggregator_id")
	}
	defer deleteAggregator(t, aggregatorID, authToken)

	aggregatorURL, ok := finishResponse["aggregator"].(string)
	if !ok || aggregatorURL == "" {
		t.Errorf("Response missing aggregator URL")
	}

	if _, hasAccessToken := finishResponse["access_token"]; hasAccessToken {
		t.Errorf("Response should NOT include access_token (must be stored server-side)")
	}

	t.Logf("Authorization code flow completed: id=%s, url=%s", aggregatorID, aggregatorURL)
}

func TestRegistration_AuthorizationCode_InvalidState(t *testing.T) {
	oidcProvider, err := mocks.NewOIDCProvider(testEnv)
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}
	defer oidcProvider.Close()

	ownerWebID := "https://test.auth_code.invalid_state/webid#me"
	authToken := createAuthToken(t, oidcProvider, ownerWebID, true)
	testClientId := oidcProvider.ClientMetadataURL([]string{"http://test.example/callback"})

	umaServer := mocks.NewUMAAuthorizationServer()
	defer umaServer.Close()

	reqBody := map[string]interface{}{
		"registration_type":    "authorization_code",
		"authorization_server": umaServer.URL(),
		"client_id":            testClientId,
	}
	body, _ := json.Marshal(reqBody)

	req, err := http.NewRequest("POST", testEnv.AggregatorServerURL+testEnv.RegistrationPath, bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Start request failed: %v", err)
	}
	defer resp.Body.Close()

	parseAuthCodeStartResponse(t, resp)

	finishBody := map[string]interface{}{
		"registration_type": "authorization_code",
		"code":              "fake-code",
		"redirect_uri":      "http://test.example/callback",
		"state":             "invalid-state-12345",
	}
	finishJSON, _ := json.Marshal(finishBody)

	finishReq, err := http.NewRequest("POST", testEnv.AggregatorServerURL+testEnv.RegistrationPath, bytes.NewBuffer(finishJSON))
	if err != nil {
		t.Fatalf("Failed to create finish request: %v", err)
	}
	finishReq.Header.Set("Content-Type", "application/json")
	finishReq.Header.Set("Authorization", "Bearer "+authToken)

	finishResp, err := client.Do(finishReq)
	if err != nil {
		t.Fatalf("Finish request failed: %v", err)
	}
	defer finishResp.Body.Close()

	if finishResp.StatusCode != http.StatusBadRequest && finishResp.StatusCode != http.StatusForbidden {
		bodyBytes, _ := io.ReadAll(finishResp.Body)
		t.Fatalf("Expected 400 or 403 with invalid state, got %d: %s", finishResp.StatusCode, string(bodyBytes))
	}

	t.Logf("Correctly rejected invalid state with status %d", finishResp.StatusCode)
}

func TestRegistration_AuthorizationCode_InvalidCode(t *testing.T) {
	oidcProvider, err := mocks.NewOIDCProvider(testEnv)
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}
	defer oidcProvider.Close()

	ownerWebID := "https://test.auth_code.invalid_code/webid#me"
	authToken := createAuthToken(t, oidcProvider, ownerWebID, true)
	testClientId := oidcProvider.ClientMetadataURL([]string{"http://test.example/callback"})

	umaServer := mocks.NewUMAAuthorizationServer()
	defer umaServer.Close()

	reqBody := map[string]interface{}{
		"registration_type":    "authorization_code",
		"authorization_server": umaServer.URL(),
		"client_id":            testClientId,
	}
	body, _ := json.Marshal(reqBody)

	req, err := http.NewRequest("POST", testEnv.AggregatorServerURL+testEnv.RegistrationPath, bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Start request failed: %v", err)
	}
	defer resp.Body.Close()

	start := parseAuthCodeStartResponse(t, resp)
	state := start.State

	finishBody := map[string]interface{}{
		"registration_type": "authorization_code",
		"code":              "invalid-authorization-code",
		"redirect_uri":      "https://app.example/callback",
		"state":             state,
	}
	finishJSON, _ := json.Marshal(finishBody)

	finishReq, err := http.NewRequest("POST", testEnv.AggregatorServerURL+testEnv.RegistrationPath, bytes.NewBuffer(finishJSON))
	if err != nil {
		t.Fatalf("Failed to create finish request: %v", err)
	}
	finishReq.Header.Set("Content-Type", "application/json")
	finishReq.Header.Set("Authorization", "Bearer "+authToken)

	finishResp, err := client.Do(finishReq)
	if err != nil {
		t.Fatalf("Finish request failed: %v", err)
	}
	defer finishResp.Body.Close()

	if finishResp.StatusCode == http.StatusCreated || finishResp.StatusCode == http.StatusOK {
		t.Fatalf("Expected error with invalid code, got %d", finishResp.StatusCode)
	}

	t.Logf("Correctly rejected invalid authorization code with status %d", finishResp.StatusCode)
}

func TestRegistration_ClientCredentials_Create(t *testing.T) {
	oidcProvider, err := mocks.NewOIDCProvider(testEnv)
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}
	defer oidcProvider.Close()

	ownerWebID := "https://test.auth_code.invalid_code/webid#me"
	authToken := createAuthToken(t, oidcProvider, ownerWebID, true)
	oidcProvider.RegisterClient("test-client", "test-pass", []string{}, []string{
		"client_credentials",
	})

	umaServer := mocks.NewUMAAuthorizationServer()
	defer umaServer.Close()

	reqBody := map[string]interface{}{
		"registration_type":    "client_credentials",
		"authorization_server": umaServer.URL(),
		"client_id":            "test-client",
		"client_secret":        "test-pass",
	}
	body, _ := json.Marshal(reqBody)

	req, err := http.NewRequest("POST", testEnv.AggregatorServerURL+testEnv.RegistrationPath, bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected 201 Created, got %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	aggregatorID, ok := response["aggregator_id"].(string)
	if !ok || aggregatorID == "" {
		t.Errorf("Response missing aggregator_id")
	}
	defer deleteAggregator(t, aggregatorID, authToken)

	aggregatorURL, ok := response["aggregator"].(string)
	if !ok || aggregatorURL == "" {
		t.Errorf("Response missing aggregator URL")
	}

	if _, hasAccessToken := response["access_token"]; hasAccessToken {
		t.Errorf("Response should NOT include access_token (must be stored server-side)")
	}
	if _, hasRefreshToken := response["refresh_token"]; hasRefreshToken {
		t.Errorf("Response should NOT include refresh_token (must be stored server-side)")
	}
	if _, hasPassword := response["password"]; hasPassword {
		t.Errorf("Response should NOT include password")
	}

	t.Logf("Client credentials flow completed: id=%s, url=%s", aggregatorID, aggregatorURL)
}

func TestRegistration_ClientCredentials_InvalidCredentials(t *testing.T) {
	oidcProvider, err := mocks.NewOIDCProvider(testEnv)
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}
	defer oidcProvider.Close()

	ownerWebID := "https://test.client_credentials.invalid_creds/webid#me"
	authToken := createAuthToken(t, oidcProvider, ownerWebID, true)
	oidcProvider.RegisterClient("test-client", "test-pass", []string{}, []string{
		"client_credentials",
	})

	umaServer := mocks.NewUMAAuthorizationServer()
	defer umaServer.Close()

	reqBody := map[string]interface{}{
		"registration_type":    "client_credentials",
		"authorization_server": umaServer.URL(),
		"client_id":            "test-client",
		"client_secret":        "wrong-password",
	}
	body, _ := json.Marshal(reqBody)

	req, err := http.NewRequest("POST", testEnv.AggregatorServerURL+testEnv.RegistrationPath, bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusBadGateway {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Errorf("Expected 401/403/502 with invalid credentials, got %d: %s", resp.StatusCode, string(bodyBytes))
	}

	t.Logf("Correctly rejected invalid credentials with status %d", resp.StatusCode)
}

func TestRegistration_Provision_Create(t *testing.T) {
	/*
		oidcProvider, err := mocks.NewOIDCProvider(testEnv)
		if err != nil {
			t.Fatalf("Failed to create OIDC provider: %v", err)
		}
		defer oidcProvider.Close()

		umaServer := mocks.NewUMAAuthorizationServer()
		defer umaServer.Close()

		ownerWebID := "https://test.provision/webid#me"
		authToken := createAuthToken(t, oidcProvider, ownerWebID, true)
		targetWebID := oidcProvider.URL() + "/webid#me"
		oidcProvider.RegisterUser(targetWebID, "provision-user", "provision-pass")
		updateProvisionConfig(t, testEnv.ProvisionClientID, testEnv.ProvisionClientSecret, targetWebID, oidcProvider.URL(), umaServer.URL())

		reqBody := map[string]interface{}{
			"registration_type":    "provision",
			"authorization_server": umaServer.URL(),
		}
		body, _ := json.Marshal(reqBody)

		req, err := http.NewRequest("POST", testEnv.AggregatorServerURL+testEnv.RegistrationPath, bytes.NewBuffer(body))
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+authToken)

		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusCreated {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Fatalf("Expected 201 Created, got %d: %s", resp.StatusCode, string(bodyBytes))
		}

		var response map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		aggregatorID, ok := response["aggregator_id"].(string)
		if !ok || aggregatorID == "" {
			t.Errorf("Response missing aggregator_id")
		}

		subject, ok := response["subject"].(string)
		if !ok || subject == "" {
			t.Errorf("Response missing subject")
		} else if subject != targetWebID {
			t.Errorf("Expected subject %s, got %s", targetWebID, subject)
		}

		t.Logf("Provision flow created aggregator %s", aggregatorID)
	*/
}

func TestRegistration_Provision_ReRegisterOnClientURIConflict(t *testing.T) {
	/*
		oidcProvider, err := mocks.NewOIDCProvider(testEnv)
		if err != nil {
			t.Fatalf("Failed to create OIDC provider: %v", err)
		}
		defer oidcProvider.Close()

		ownerWebID := "https://owner.example/webid#me"
		authToken := createAuthToken(t, oidcProvider, ownerWebID, true)

		umaServer := mocks.NewUMAAuthorizationServer()
		umaServer.EnableClientURIConflicts()
		defer umaServer.Close()

		aggregatorID := createAggregatorViaProvision(t, oidcProvider, authToken, umaServer.URL())
		if aggregatorID == "" {
			t.Fatal("Expected aggregator ID for first provision")
		}

		aggregatorID = createAggregatorViaProvision(t, oidcProvider, authToken, umaServer.URL())
		if aggregatorID == "" {
			t.Fatal("Expected aggregator ID for re-provision")
		}
	*/
}

func TestRegistration_Provision_InvalidCredentials(t *testing.T) {
	/*
		oidcProvider, err := mocks.NewOIDCProvider(testEnv)
		if err != nil {
			t.Fatalf("Failed to create OIDC provider: %v", err)
		}
		defer oidcProvider.Close()

		ownerWebID := "https://owner.example/webid#me"
		authToken := createAuthToken(t, oidcProvider, ownerWebID, true)

		umaServer := mocks.NewUMAAuthorizationServer()
		defer umaServer.Close()

		targetWebID := oidcProvider.URL() + "/webid#me"
		validClientID := "provision-client-id-invalid-creds"
		validClientSecret := "provision-client-secret-valid"
		oidcProvider.RegisterClient(validClientID, validClientSecret, []string{}, []string{"client_credentials"})
		oidcProvider.RegisterUser(targetWebID, "provision-user", "provision-pass")
		updateProvisionConfig(t, validClientID, "wrong-secret", targetWebID, oidcProvider.URL(), umaServer.URL())

		reqBody := map[string]interface{}{
			"registration_type": "provision",
		}
		body, _ := json.Marshal(reqBody)

		req, err := http.NewRequest("POST", testEnv.AggregatorServerURL+testEnv.RegistrationPath, bytes.NewBuffer(body))
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+authToken)

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusBadGateway {
			bodyBytes, _ := io.ReadAll(resp.Body)
			t.Fatalf("Expected 401/403/502 for invalid credentials, got %d: %s", resp.StatusCode, string(bodyBytes))
		}

		t.Logf("Provision correctly rejected invalid credentials with status %d", resp.StatusCode)
	*/
}

func TestRegistration_TokenUpdate_ClientCredentials(t *testing.T) {
	oidcProvider, err := mocks.NewOIDCProvider(testEnv)
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}
	defer oidcProvider.Close()

	ownerWebID := "https://test.client_credentials.update/webid#me"
	authToken := createAuthToken(t, oidcProvider, ownerWebID, true)
	oidcProvider.RegisterClient("test-client", "test-pass", []string{}, []string{
		"client_credentials",
	})

	umaServer := mocks.NewUMAAuthorizationServer()
	defer umaServer.Close()

	createBody := map[string]interface{}{
		"registration_type":    "client_credentials",
		"authorization_server": umaServer.URL(),
		"client_id":            "test-client",
		"client_secret":        "test-pass",
	}
	body, _ := json.Marshal(createBody)

	client := &http.Client{}
	createReq, err := http.NewRequest("POST", testEnv.AggregatorServerURL+testEnv.RegistrationPath, bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("Authorization", "Bearer "+authToken)

	createResp, err := client.Do(createReq)
	if err != nil {
		t.Fatalf("Create request failed: %v", err)
	}
	defer createResp.Body.Close()

	if createResp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(createResp.Body)
		t.Fatalf("Expected 201 Created, got %d: %s", createResp.StatusCode, string(bodyBytes))
	}

	var createResponse map[string]interface{}
	if err := json.NewDecoder(createResp.Body).Decode(&createResponse); err != nil {
		t.Fatalf("Failed to decode create response: %v", err)
	}

	aggregatorID, ok := createResponse["aggregator_id"].(string)
	if !ok || aggregatorID == "" {
		t.Fatalf("Response missing aggregator_id")
	}
	defer deleteAggregator(t, aggregatorID, authToken)

	updatedClientID := "user-client-id-updated"
	updatedClientSecret := "user-client-secret-updated"
	oidcProvider.RegisterClient(updatedClientID, updatedClientSecret, []string{}, []string{"client_credentials"})

	updateBody := map[string]interface{}{
		"registration_type":    "client_credentials",
		"authorization_server": umaServer.URL(),
		"client_id":            updatedClientID,
		"client_secret":        updatedClientSecret,
		"aggregator_id":        aggregatorID,
	}
	updateJSON, _ := json.Marshal(updateBody)

	updateReq, err := http.NewRequest("POST", testEnv.AggregatorServerURL+testEnv.RegistrationPath, bytes.NewBuffer(updateJSON))
	if err != nil {
		t.Fatalf("Failed to create update request: %v", err)
	}
	updateReq.Header.Set("Content-Type", "application/json")
	updateReq.Header.Set("Authorization", "Bearer "+authToken)

	updateResp, err := client.Do(updateReq)
	if err != nil {
		t.Fatalf("Update request failed: %v", err)
	}
	defer updateResp.Body.Close()

	if updateResp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(updateResp.Body)
		t.Fatalf("Expected 200 OK on update, got %d: %s", updateResp.StatusCode, string(bodyBytes))
	}

	var updateResponse map[string]interface{}
	if err := json.NewDecoder(updateResp.Body).Decode(&updateResponse); err != nil {
		t.Fatalf("Failed to decode update response: %v", err)
	}

	if updateResponse["aggregator_id"].(string) != aggregatorID {
		t.Errorf("aggregator_id changed during update")
	}

	t.Logf("Client credentials token update successful for aggregator %s", aggregatorID)
}

func TestRegistration_TokenUpdate_AuthorizationCode(t *testing.T) {
	oidcProvider, err := mocks.NewOIDCProvider(testEnv)
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}
	defer oidcProvider.Close()

	ownerWebID := "https://test.auth_code.update/webid#me"
	oidcProvider.RegisterUser(ownerWebID, "auth-finish-solid", "auth-finish-solid-pass")
	authToken := createAuthToken(t, oidcProvider, ownerWebID, true)
	testClientId := oidcProvider.ClientMetadataURL([]string{"http://test.example/callback"})

	umaServer := mocks.NewUMAAuthorizationServer()
	defer umaServer.Close()

	createBody := map[string]interface{}{
		"registration_type":    "authorization_code",
		"authorization_server": umaServer.URL(),
		"client_id":            testClientId,
	}
	body, _ := json.Marshal(createBody)

	client := &http.Client{}
	startReq, err := http.NewRequest("POST", testEnv.AggregatorServerURL+testEnv.RegistrationPath, bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to create start request: %v", err)
	}
	startReq.Header.Set("Content-Type", "application/json")
	startReq.Header.Set("Authorization", "Bearer "+authToken)

	startResp, err := client.Do(startReq)
	if err != nil {
		t.Fatalf("Start request failed: %v", err)
	}
	defer startResp.Body.Close()

	if startResp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(startResp.Body)
		t.Fatalf("Expected 201 Created on start, got %d: %s", startResp.StatusCode, string(bodyBytes))
	}

	start := parseAuthCodeStartResponse(t, startResp)
	state := start.State
	codeChallenge := start.CodeChallenge
	startClientID := start.AggregatorClientID

	authReq, err := http.NewRequest("GET", oidcProvider.URL()+"/authorize", nil)
	if err != nil {
		t.Fatalf("Failed to create authorize request: %v", err)
	}
	q := authReq.URL.Query()
	q.Set("response_type", "code")
	q.Set("client_id", startClientID)
	q.Set("redirect_uri", "http://test.example/callback")
	q.Set("scope", "openid webid offline_access")
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)
	authReq.URL.RawQuery = q.Encode()

	authClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	authResp, err := authClient.Do(authReq)
	if err != nil {
		t.Fatalf("Authorization request failed: %v", err)
	}
	defer authResp.Body.Close()

	if authResp.StatusCode != http.StatusFound {
		bodyBytes, _ := io.ReadAll(authResp.Body)
		t.Fatalf("Expected 302 redirect from authorize endpoint, got %d: %s", authResp.StatusCode, string(bodyBytes))
	}

	location := authResp.Header.Get("Location")
	if location == "" {
		t.Fatalf("No Location header in authorize response")
	}

	redirectURL, err := http.NewRequest("GET", location, nil)
	if err != nil {
		t.Fatalf("Failed to parse redirect URL: %v", err)
	}

	code := redirectURL.URL.Query().Get("code")
	if code == "" {
		t.Fatalf("No authorization code in redirect")
	}

	finishBody := map[string]interface{}{
		"registration_type": "authorization_code",
		"code":              code,
		"redirect_uri":      "http://test.example/callback",
		"state":             state,
	}
	finishJSON, _ := json.Marshal(finishBody)

	finishReq, err := http.NewRequest("POST", testEnv.AggregatorServerURL+testEnv.RegistrationPath, bytes.NewBuffer(finishJSON))
	if err != nil {
		t.Fatalf("Failed to create finish request: %v", err)
	}
	finishReq.Header.Set("Content-Type", "application/json")
	finishReq.Header.Set("Authorization", "Bearer "+authToken)

	finishResp, err := client.Do(finishReq)
	if err != nil {
		t.Fatalf("Finish request failed: %v", err)
	}
	defer finishResp.Body.Close()

	if finishResp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(finishResp.Body)
		t.Fatalf("Expected 201 Created on finish, got %d: %s", finishResp.StatusCode, string(bodyBytes))
	}

	var finishResponse map[string]interface{}
	if err := json.NewDecoder(finishResp.Body).Decode(&finishResponse); err != nil {
		t.Fatalf("Failed to decode finish response: %v", err)
	}

	aggregatorID, ok := finishResponse["aggregator_id"].(string)
	if !ok || aggregatorID == "" {
		t.Fatalf("Response missing aggregator_id")
	}
	defer deleteAggregator(t, aggregatorID, authToken)

	updateStartBody := map[string]interface{}{
		"registration_type":    "authorization_code",
		"authorization_server": umaServer.URL(),
		"client_id":            testClientId,
		"aggregator_id":        aggregatorID,
	}
	updateStartJSON, _ := json.Marshal(updateStartBody)

	updateStartReq, err := http.NewRequest("POST", testEnv.AggregatorServerURL+testEnv.RegistrationPath, bytes.NewBuffer(updateStartJSON))
	if err != nil {
		t.Fatalf("Failed to create update start request: %v", err)
	}
	updateStartReq.Header.Set("Content-Type", "application/json")
	updateStartReq.Header.Set("Authorization", "Bearer "+authToken)

	updateStartResp, err := client.Do(updateStartReq)
	if err != nil {
		t.Fatalf("Update start request failed: %v", err)
	}
	defer updateStartResp.Body.Close()

	if updateStartResp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(updateStartResp.Body)
		t.Fatalf("Expected 201 Created on update start, got %d: %s", updateStartResp.StatusCode, string(bodyBytes))
	}

	updateStart := parseAuthCodeStartResponse(t, updateStartResp)
	updateState := updateStart.State
	updateCodeChallenge := updateStart.CodeChallenge
	updateClientID := updateStart.AggregatorClientID

	updateAuthReq, err := http.NewRequest("GET", oidcProvider.URL()+"/authorize", nil)
	if err != nil {
		t.Fatalf("Failed to create update authorize request: %v", err)
	}
	q = updateAuthReq.URL.Query()
	q.Set("response_type", "code")
	q.Set("client_id", updateClientID)
	q.Set("redirect_uri", "http://test.example/callback")
	q.Set("scope", "openid webid offline_access")
	q.Set("code_challenge", updateCodeChallenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", updateState)
	updateAuthReq.URL.RawQuery = q.Encode()

	updateAuthResp, err := authClient.Do(updateAuthReq)
	if err != nil {
		t.Fatalf("Update authorization request failed: %v", err)
	}
	defer updateAuthResp.Body.Close()

	if updateAuthResp.StatusCode != http.StatusFound {
		bodyBytes, _ := io.ReadAll(updateAuthResp.Body)
		t.Fatalf("Expected 302 redirect from update authorize endpoint, got %d: %s", updateAuthResp.StatusCode, string(bodyBytes))
	}

	updateLocation := updateAuthResp.Header.Get("Location")
	if updateLocation == "" {
		t.Fatalf("No Location header in update authorize response")
	}

	updateRedirectURL, err := http.NewRequest("GET", updateLocation, nil)
	if err != nil {
		t.Fatalf("Failed to parse update redirect URL: %v", err)
	}

	updateCode := updateRedirectURL.URL.Query().Get("code")
	if updateCode == "" {
		t.Fatalf("No authorization code in update redirect")
	}

	updateFinishBody := map[string]interface{}{
		"registration_type": "authorization_code",
		"code":              updateCode,
		"redirect_uri":      "http://test.example/callback",
		"state":             updateState,
	}
	updateFinishJSON, _ := json.Marshal(updateFinishBody)

	updateFinishReq, err := http.NewRequest("POST", testEnv.AggregatorServerURL+testEnv.RegistrationPath, bytes.NewBuffer(updateFinishJSON))
	if err != nil {
		t.Fatalf("Failed to create update finish request: %v", err)
	}
	updateFinishReq.Header.Set("Content-Type", "application/json")
	updateFinishReq.Header.Set("Authorization", "Bearer "+authToken)

	updateFinishResp, err := client.Do(updateFinishReq)
	if err != nil {
		t.Fatalf("Update finish request failed: %v", err)
	}
	defer updateFinishResp.Body.Close()

	if updateFinishResp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(updateFinishResp.Body)
		t.Fatalf("Expected 200 OK on update finish, got %d: %s", updateFinishResp.StatusCode, string(bodyBytes))
	}

	var updateFinishResponse map[string]interface{}
	if err := json.NewDecoder(updateFinishResp.Body).Decode(&updateFinishResponse); err != nil {
		t.Fatalf("Failed to decode update finish response: %v", err)
	}

	if updateFinishResponse["aggregator_id"].(string) != aggregatorID {
		t.Errorf("aggregator_id changed during update")
	}

	t.Logf("Authorization code token update successful for aggregator %s", aggregatorID)
}

func TestRegistration_TokenUpdate_Provision(t *testing.T) {
	/*
		oidcProvider, err := mocks.NewOIDCProvider()
		if err != nil {
			t.Fatalf("Failed to create OIDC provider: %v", err)
		}
		defer oidcProvider.Close()

		ownerWebID := "https://owner.example/webid#me"
		authToken := createAuthToken(t, oidcProvider, ownerWebID)

		updateBody := map[string]interface{}{
			"registration_type": "provision",
			"aggregator_id":     "dummy-aggregator-id",
		}
		body, _ := json.Marshal(updateBody)

		req, err := http.NewRequest("POST", testEnv.AggregatorServerURL+"/registration", bytes.NewBuffer(body))
		if err != nil {
			t.Fatalf("Failed to create update request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+authToken)

		client := &http.Client{}
		updateResp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Update request failed: %v", err)
		}
		defer updateResp.Body.Close()

		if updateResp.StatusCode != http.StatusBadRequest {
			bodyBytes, _ := io.ReadAll(updateResp.Body)
			t.Fatalf("Expected 400 Bad Request for provision update, got %d: %s", updateResp.StatusCode, string(bodyBytes))
		}

		t.Logf("Provision update correctly returns 400 Bad Request")
	*/
}

func TestRegistration_TokenUpdate_None(t *testing.T) {
	aggregatorID := createAggregatorViaNone(t)
	defer deleteAggregator(t, aggregatorID, "")

	updateBody := map[string]interface{}{
		"registration_type": "none",
		"aggregator_id":     aggregatorID,
	}
	body, _ := json.Marshal(updateBody)

	req, err := http.NewRequest("POST", testEnv.AggregatorServerURL+"/registration", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to create none update request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	updateResp, err := client.Do(req)
	if err != nil {
		t.Fatalf("None update request failed: %v", err)
	}
	defer updateResp.Body.Close()

	if updateResp.StatusCode != http.StatusBadRequest {
		bodyBytes, _ := io.ReadAll(updateResp.Body)
		t.Fatalf("Expected 400 Bad Request for none update, got %d: %s", updateResp.StatusCode, string(bodyBytes))
	}
}

func TestRegistration_Delete_ClientCredentials(t *testing.T) {
	oidcProvider, err := mocks.NewOIDCProvider(testEnv)
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}
	defer oidcProvider.Close()

	ownerWebID := "https://test.client_credentials.delete/webid#me"
	authToken := createAuthToken(t, oidcProvider, ownerWebID, true)

	umaServer := mocks.NewUMAAuthorizationServer()
	defer umaServer.Close()

	aggregatorID := createAggregatorViaClientCredentials(t, oidcProvider, authToken, umaServer.URL())
	deleteAggregator(t, aggregatorID, authToken)
	t.Logf("Successfully deleted client_credentials aggregator %s", aggregatorID)
}

func TestRegistration_Delete_AuthorizationCode(t *testing.T) {
	oidcProvider, err := mocks.NewOIDCProvider(testEnv)
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}
	defer oidcProvider.Close()

	ownerWebID := "https://test.auth_code.delete/webid#me"
	authToken := createAuthToken(t, oidcProvider, ownerWebID, true)

	umaServer := mocks.NewUMAAuthorizationServer()
	defer umaServer.Close()

	aggregatorID := createAggregatorViaAuthorizationCode(t, oidcProvider, authToken, umaServer.URL())
	deleteAggregator(t, aggregatorID, authToken)
	t.Logf("Successfully deleted authorization_code aggregator %s", aggregatorID)
}

func TestRegistration_Delete_Provision(t *testing.T) {
	/*
		oidcProvider, err := mocks.NewOIDCProvider()
		if err != nil {
			t.Fatalf("Failed to create OIDC provider: %v", err)
		}
		defer oidcProvider.Close()

		ownerWebID := "https://owner.example/webid#me"
		authToken := createAuthToken(t, oidcProvider, ownerWebID)

		umaServer := mocks.NewUMAAuthorizationServer()
		defer umaServer.Close()

		aggregatorID := createAggregatorViaProvision(t, oidcProvider, authToken, umaServer.URL())
		deleteAggregator(t, aggregatorID, authToken)
		t.Logf("Successfully deleted provision aggregator %s", aggregatorID)
	*/
}

func TestRegistration_Delete_NotFound(t *testing.T) {
	oidcProvider, err := mocks.NewOIDCProvider(testEnv)
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}
	defer oidcProvider.Close()

	ownerWebID := "https://test.delete.not_found/webid#me"
	authToken := createAuthToken(t, oidcProvider, ownerWebID, true)

	deleteBody := map[string]interface{}{
		"aggregator_id": "non-existent-aggregator-id-12345",
	}
	deleteJSON, _ := json.Marshal(deleteBody)

	deleteReq, err := http.NewRequest("DELETE", testEnv.AggregatorServerURL+"/registration", bytes.NewBuffer(deleteJSON))
	if err != nil {
		t.Fatalf("Failed to create delete request: %v", err)
	}
	deleteReq.Header.Set("Content-Type", "application/json")
	deleteReq.Header.Set("Authorization", "Bearer "+authToken)

	client := &http.Client{}
	deleteResp, err := client.Do(deleteReq)
	if err != nil {
		t.Fatalf("Delete request failed: %v", err)
	}
	defer deleteResp.Body.Close()

	if deleteResp.StatusCode != http.StatusNotFound && deleteResp.StatusCode != http.StatusForbidden {
		bodyBytes, _ := io.ReadAll(deleteResp.Body)
		t.Fatalf("Expected 404 Not Found or 403 Forbidden, got %d: %s", deleteResp.StatusCode, string(bodyBytes))
	}

	t.Logf("Correctly returned %d for non-existent aggregator", deleteResp.StatusCode)
}

func TestRegistration_Delete_Unauthorized(t *testing.T) {
	oidcProvider, err := mocks.NewOIDCProvider(testEnv)
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}
	defer oidcProvider.Close()

	ownerWebID := "https://test.delete.unauthorized/webid#me"
	ownerToken := createAuthToken(t, oidcProvider, ownerWebID, true)

	umaServer := mocks.NewUMAAuthorizationServer()
	defer umaServer.Close()

	aggregatorID := createAggregatorViaClientCredentials(t, oidcProvider, ownerToken, umaServer.URL())

	otherToken := createAuthToken(t, oidcProvider, "https://other.example/webid#me", true)

	deleteBody := map[string]interface{}{
		"aggregator_id": aggregatorID,
	}
	deleteJSON, _ := json.Marshal(deleteBody)

	deleteReq, err := http.NewRequest("DELETE", testEnv.AggregatorServerURL+"/registration", bytes.NewBuffer(deleteJSON))
	if err != nil {
		t.Fatalf("Failed to create delete request: %v", err)
	}
	deleteReq.Header.Set("Content-Type", "application/json")
	deleteReq.Header.Set("Authorization", "Bearer "+otherToken)

	client := &http.Client{}
	deleteResp, err := client.Do(deleteReq)
	if err != nil {
		t.Fatalf("Delete request failed: %v", err)
	}
	defer deleteResp.Body.Close()

	if deleteResp.StatusCode != http.StatusForbidden && deleteResp.StatusCode != http.StatusNotFound {
		bodyBytes, _ := io.ReadAll(deleteResp.Body)
		t.Errorf("Expected 403 Forbidden or 404 Not Found, got %d: %s", deleteResp.StatusCode, string(bodyBytes))
	}

	t.Logf("Correctly rejected unauthorized delete with status %d", deleteResp.StatusCode)
}

func TestRegistration_Unauthenticated(t *testing.T) {
	reqBody := map[string]interface{}{
		"registration_type": "provision",
	}
	body, _ := json.Marshal(reqBody)

	req, err := http.NewRequest("POST", testEnv.AggregatorServerURL+"/registration", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected 401 Unauthorized, got %d: %s", resp.StatusCode, string(bodyBytes))
	}

	t.Logf("Correctly rejected unauthenticated request")
}

func TestRegistration_InvalidRegistrationType(t *testing.T) {
	oidcProvider, err := mocks.NewOIDCProvider(testEnv)
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}
	defer oidcProvider.Close()

	ownerWebID := "https://test.invalid_reg_type/webid#me"
	authToken := createAuthToken(t, oidcProvider, ownerWebID, true)

	reqBody := map[string]interface{}{
		"registration_type": "unsupported_type",
	}
	body, _ := json.Marshal(reqBody)

	req, err := http.NewRequest("POST", testEnv.AggregatorServerURL+"/registration", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected 400 Bad Request, got %d: %s", resp.StatusCode, string(bodyBytes))
	}

	t.Logf("Correctly rejected invalid registration_type")
}

func TestRegistration_MalformedRequest(t *testing.T) {
	testCases := []struct {
		name        string
		body        string
		contentType string
		wantCode    int
	}{
		{
			name:        "invalid JSON",
			body:        `{invalid json`,
			contentType: "application/json",
			wantCode:    http.StatusBadRequest,
		},
		{
			name:        "missing registration_type",
			body:        `{}`,
			contentType: "application/json",
			wantCode:    http.StatusBadRequest,
		},
		{
			name:        "empty body",
			body:        ``,
			contentType: "application/json",
			wantCode:    http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			oidcProvider, err := mocks.NewOIDCProvider(testEnv)
			if err != nil {
				t.Fatalf("Failed to create OIDC provider: %v", err)
			}
			defer oidcProvider.Close()

			ownerWebID := "https://test.malformed/webid#me"
			authToken := createAuthToken(t, oidcProvider, ownerWebID, true)

			req, err := http.NewRequest("POST", testEnv.AggregatorServerURL+"/registration", bytes.NewBufferString(tc.body))
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			req.Header.Set("Content-Type", tc.contentType)
			req.Header.Set("Authorization", "Bearer "+authToken)

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tc.wantCode {
				bodyBytes, _ := io.ReadAll(resp.Body)
				t.Errorf("Expected status %d, got %d: %s", tc.wantCode, resp.StatusCode, string(bodyBytes))
			}
		})
	}
}
