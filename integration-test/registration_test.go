package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"aggregator-integration-test/mocks"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	testAggregatorClientIDURL  = "http://aggregator.local/client.json"
	testAggregatorClientSecret = "AtctW4sdbmjcfF9gQJIf5RoK6T6wetwG"
	testProvisionClientID      = "provision-client-id"
	testProvisionClientSecret  = "provision-client-secret"
)

// Helper function to create a valid authentication token for tests
func createAuthToken(t *testing.T, oidcProvider *mocks.OIDCProvider, webID string) string {
	// The mock provider returns the configured issuer (defaults to oidc.local).
	// The WebID uses the provider issuer base.
	mockWebID := oidcProvider.URL() + "/webid#me"

	// Create a JWT token with the WebID claim
	token, err := oidcProvider.IssueTokenForWebID(mockWebID)
	if err != nil {
		t.Fatalf("Failed to create auth token: %v", err)
	}
	return token
}

type authCodeStartResponse struct {
	AggregatorClientID  string `json:"aggregator_client_id"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	State               string `json:"state"`
}

func parseAuthCodeStartResponse(t *testing.T, resp *http.Response) authCodeStartResponse {
	t.Helper()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Expected 201 Created on start, got %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var start authCodeStartResponse
	if err := json.Unmarshal(bodyBytes, &start); err != nil {
		t.Fatalf("Failed to decode start response: %v", err)
	}

	if start.State == "" || start.CodeChallenge == "" || start.CodeChallengeMethod == "" || start.AggregatorClientID == "" {
		t.Fatalf("Start response missing required fields: %+v", start)
	}

	return start
}

func deleteAggregator(t *testing.T, aggregatorID string, authToken string) {
	t.Helper()

	deleteBody := map[string]interface{}{
		"aggregator_id": aggregatorID,
	}
	deleteJSON, _ := json.Marshal(deleteBody)

	deleteReq, err := http.NewRequest("DELETE", testEnv.AggregatorURL+"/registration", bytes.NewBuffer(deleteJSON))
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

	if deleteResp.StatusCode != http.StatusNoContent {
		bodyBytes, _ := io.ReadAll(deleteResp.Body)
		t.Fatalf("Expected 204 No Content, got %d: %s", deleteResp.StatusCode, string(bodyBytes))
	}
}

func assertWebIDDereferenceable(t *testing.T, webID string) {
	t.Helper()

	base := webID
	if idx := strings.Index(webID, "#"); idx != -1 {
		base = webID[:idx]
	}

	resp, err := http.Get(base)
	if err != nil {
		t.Fatalf("Failed to dereference webid %s: %v", base, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected 200 OK for webid %s, got %d: %s", base, resp.StatusCode, string(bodyBytes))
	}
}

func updateProvisionConfig(t *testing.T, clientID, clientSecret, webID, authorizationServer string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	configMap, err := testEnv.KubeClient.CoreV1().ConfigMaps("aggregator-app").Get(ctx, "aggregator-config", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Failed to fetch aggregator configmap: %v", err)
	}

	if configMap.Data == nil {
		configMap.Data = map[string]string{}
	}
	configMap.Data["provision_client_id"] = clientID
	configMap.Data["provision_client_secret"] = clientSecret
	configMap.Data["provision_webid"] = webID
	configMap.Data["provision_authorization_server"] = authorizationServer

	if _, err := testEnv.KubeClient.CoreV1().ConfigMaps("aggregator-app").Update(ctx, configMap, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("Failed to update aggregator configmap: %v", err)
	}

	deployment, err := testEnv.KubeClient.AppsV1().Deployments("aggregator-app").Get(ctx, "aggregator-server", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Failed to fetch aggregator deployment: %v", err)
	}

	if deployment.Spec.Template.Annotations == nil {
		deployment.Spec.Template.Annotations = map[string]string{}
	}
	deployment.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"] = time.Now().Format(time.RFC3339Nano)

	if _, err := testEnv.KubeClient.AppsV1().Deployments("aggregator-app").Update(ctx, deployment, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("Failed to restart aggregator deployment: %v", err)
	}

	waitForDeploymentReady(t, ctx, "aggregator-app", "aggregator-server")
	waitForAggregatorReady(t, ctx, testEnv.AggregatorURL+"/")
}

func waitForDeploymentReady(t *testing.T, ctx context.Context, namespace, name string) {
	t.Helper()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			t.Fatalf("Timed out waiting for %s deployment to be ready: %v", name, ctx.Err())
		case <-ticker.C:
			deployment, err := testEnv.KubeClient.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				continue
			}

			desired := int32(1)
			if deployment.Spec.Replicas != nil {
				desired = *deployment.Spec.Replicas
			}

			if deployment.Status.ObservedGeneration < deployment.Generation {
				continue
			}
			if deployment.Status.Replicas != desired {
				continue
			}
			if deployment.Status.UpdatedReplicas < desired {
				continue
			}
			if deployment.Status.ReadyReplicas < desired {
				continue
			}
			if deployment.Status.AvailableReplicas < desired {
				continue
			}

			return
		}
	}
}

func waitForAggregatorReady(t *testing.T, ctx context.Context, url string) {
	t.Helper()

	client := &http.Client{
		Timeout: 2 * time.Second,
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			t.Fatalf("Timed out waiting for aggregator at %s: %v", url, ctx.Err())
		case <-ticker.C:
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				continue
			}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
	}
}

func createAggregatorViaProvision(t *testing.T, oidcProvider *mocks.OIDCProvider, authToken string, umaServerURL string) string {
	t.Helper()

	targetWebID := oidcProvider.URL() + "/webid#me"
	oidcProvider.RegisterClient(testProvisionClientID, testProvisionClientSecret, []string{}, []string{"client_credentials"})
	oidcProvider.RegisterUser(targetWebID, "provision-user", "provision-pass")
	updateProvisionConfig(t, testProvisionClientID, testProvisionClientSecret, targetWebID, umaServerURL)

	createBody := map[string]interface{}{
		"registration_type":    "provision",
		"authorization_server": umaServerURL,
	}
	body, _ := json.Marshal(createBody)

	req, err := http.NewRequest("POST", testEnv.AggregatorURL+"/registration", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to create provision request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Provision request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected 201 Created for provision, got %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode provision response: %v", err)
	}
	aggregatorID, ok := response["aggregator_id"].(string)
	if !ok || aggregatorID == "" {
		t.Fatalf("Provision response missing aggregator_id")
	}

	return aggregatorID
}

func createAggregatorViaClientCredentials(t *testing.T, oidcProvider *mocks.OIDCProvider, authToken string, umaServerURL string) string {
	t.Helper()

	targetWebID := oidcProvider.URL() + "/webid#me"
	targetClientID := "delete-client-id"
	targetClientSecret := "delete-client-secret"
	oidcProvider.RegisterClient(targetClientID, targetClientSecret, []string{}, []string{"client_credentials"})
	oidcProvider.RegisterUser(targetWebID, "delete-user", "delete-pass")

	createBody := map[string]interface{}{
		"registration_type":    "client_credentials",
		"authorization_server": umaServerURL,
		"webid":                targetWebID,
		"client_id":            targetClientID,
		"client_secret":        targetClientSecret,
	}
	body, _ := json.Marshal(createBody)

	req, err := http.NewRequest("POST", testEnv.AggregatorURL+"/registration", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to create client_credentials request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Client credentials request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected 201 Created for client_credentials, got %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode client_credentials response: %v", err)
	}
	aggregatorID, ok := response["aggregator_id"].(string)
	if !ok || aggregatorID == "" {
		t.Fatalf("Client credentials response missing aggregator_id")
	}

	return aggregatorID
}

func createAggregatorViaAuthorizationCode(t *testing.T, oidcProvider *mocks.OIDCProvider, authToken string, umaServerURL string) string {
	t.Helper()

	redirectURI := "https://app.example/callback"
	oidcProvider.RegisterClient(testAggregatorClientIDURL, testAggregatorClientSecret, []string{redirectURI}, []string{"authorization_code"})
	appClientID := oidcProvider.ClientMetadataURL([]string{redirectURI})

	startBody := map[string]interface{}{
		"registration_type":    "authorization_code",
		"authorization_server": umaServerURL,
		"client_id":            appClientID,
	}
	startJSON, _ := json.Marshal(startBody)

	client := &http.Client{}
	startReq, err := http.NewRequest("POST", testEnv.AggregatorURL+"/registration", bytes.NewBuffer(startJSON))
	if err != nil {
		t.Fatalf("Failed to create authorization_code start request: %v", err)
	}
	startReq.Header.Set("Content-Type", "application/json")
	startReq.Header.Set("Authorization", "Bearer "+authToken)

	startResp, err := client.Do(startReq)
	if err != nil {
		t.Fatalf("Authorization_code start request failed: %v", err)
	}
	defer startResp.Body.Close()

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
	q.Set("redirect_uri", redirectURI)
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
		"redirect_uri":      redirectURI,
		"state":             state,
	}
	finishJSON, _ := json.Marshal(finishBody)

	finishReq, err := http.NewRequest("POST", testEnv.AggregatorURL+"/registration", bytes.NewBuffer(finishJSON))
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
		t.Fatalf("Authorization_code response missing aggregator_id")
	}

	return aggregatorID
}

func TestRegistration_Provision_Create(t *testing.T) {
	oidcProvider, err := mocks.NewOIDCProvider()
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}
	defer oidcProvider.Close()

	ownerWebID := "https://owner.example/webid#me"
	authToken := createAuthToken(t, oidcProvider, ownerWebID)

	umaServer := mocks.NewUMAAuthorizationServer()
	defer umaServer.Close()

	targetWebID := oidcProvider.URL() + "/webid#me"
	oidcProvider.RegisterClient(testProvisionClientID, testProvisionClientSecret, []string{}, []string{"client_credentials"})
	oidcProvider.RegisterUser(targetWebID, "provision-user", "provision-pass")
	updateProvisionConfig(t, testProvisionClientID, testProvisionClientSecret, targetWebID, umaServer.URL())

	reqBody := map[string]interface{}{
		"registration_type":    "provision",
		"authorization_server": umaServer.URL(),
	}
	body, _ := json.Marshal(reqBody)

	req, err := http.NewRequest("POST", testEnv.AggregatorURL+"/registration", bytes.NewBuffer(body))
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

	webID, ok := response["webid"].(string)
	if !ok || webID == "" {
		t.Errorf("Response missing webid")
	} else {
		if webID != targetWebID {
			t.Errorf("Expected webid %s, got %s", targetWebID, webID)
		}
		assertWebIDDereferenceable(t, webID)
	}

	t.Logf("Provision flow created aggregator %s", aggregatorID)
}

func TestRegistration_Provision_InvalidCredentials(t *testing.T) {
	oidcProvider, err := mocks.NewOIDCProvider()
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}
	defer oidcProvider.Close()

	ownerWebID := "https://owner.example/webid#me"
	authToken := createAuthToken(t, oidcProvider, ownerWebID)

	umaServer := mocks.NewUMAAuthorizationServer()
	defer umaServer.Close()

	targetWebID := oidcProvider.URL() + "/webid#me"
	validClientID := "provision-client-id-invalid-creds"
	validClientSecret := "provision-client-secret-valid"
	oidcProvider.RegisterClient(validClientID, validClientSecret, []string{}, []string{"client_credentials"})
	oidcProvider.RegisterUser(targetWebID, "provision-user", "provision-pass")
	updateProvisionConfig(t, validClientID, "wrong-secret", targetWebID, umaServer.URL())

	reqBody := map[string]interface{}{
		"registration_type": "provision",
	}
	body, _ := json.Marshal(reqBody)

	req, err := http.NewRequest("POST", testEnv.AggregatorURL+"/registration", bytes.NewBuffer(body))
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
}

func TestRegistration_Provision_InvalidWebID(t *testing.T) {
	oidcProvider, err := mocks.NewOIDCProvider()
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}
	defer oidcProvider.Close()

	ownerWebID := "https://owner.example/webid#me"
	authToken := createAuthToken(t, oidcProvider, ownerWebID)

	umaServer := mocks.NewUMAAuthorizationServer()
	defer umaServer.Close()

	invalidWebID := "http://127.0.0.1:1/webid#me"
	clientID := "provision-client-id-invalid-webid"
	clientSecret := "provision-client-secret-invalid-webid"
	oidcProvider.RegisterClient(clientID, clientSecret, []string{}, []string{"client_credentials"})
	updateProvisionConfig(t, clientID, clientSecret, invalidWebID, umaServer.URL())

	reqBody := map[string]interface{}{
		"registration_type": "provision",
	}
	body, _ := json.Marshal(reqBody)

	req, err := http.NewRequest("POST", testEnv.AggregatorURL+"/registration", bytes.NewBuffer(body))
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

	if resp.StatusCode != http.StatusInternalServerError {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected 500 for invalid WebID, got %d: %s", resp.StatusCode, string(bodyBytes))
	}

	t.Logf("Provision correctly rejected invalid WebID with status %d", resp.StatusCode)
}

func TestRegistration_AuthorizationCode_Start(t *testing.T) {
	oidcProvider, err := mocks.NewOIDCProvider()
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}
	defer oidcProvider.Close()

	ownerWebID := "https://owner.example/webid#me"
	authToken := createAuthToken(t, oidcProvider, ownerWebID)

	umaServer := mocks.NewUMAAuthorizationServer()

	defer umaServer.Close()

	redirectURI := "https://app.example/callback"
	appClientID := oidcProvider.ClientMetadataURL([]string{redirectURI})

	reqBody := map[string]interface{}{
		"registration_type":    "authorization_code",
		"authorization_server": umaServer.URL(),
		"client_id":            appClientID,
	}
	body, _ := json.Marshal(reqBody)

	req, err := http.NewRequest("POST", testEnv.AggregatorURL+"/registration", bytes.NewBuffer(body))
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

	if start.AggregatorClientID != testAggregatorClientIDURL {
		t.Errorf("Expected aggregator_client_id %s, got %s", testAggregatorClientIDURL, start.AggregatorClientID)
	}
	if start.CodeChallengeMethod != "S256" {
		t.Errorf("Expected code_challenge_method S256, got %s", start.CodeChallengeMethod)
	}

	t.Logf("Authorization code flow started: aggregator_client_id=%s, state=%s", start.AggregatorClientID, start.State)
}

func TestRegistration_AuthorizationCode_Finish(t *testing.T) {
	oidcProvider, err := mocks.NewOIDCProvider()
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}
	defer oidcProvider.Close()

	ownerWebID := "https://owner.example/webid#me"
	authToken := createAuthToken(t, oidcProvider, ownerWebID)

	umaServer := mocks.NewUMAAuthorizationServer()

	defer umaServer.Close()

	redirectURI := "https://app.example/callback"

	oidcProvider.RegisterClient(testAggregatorClientIDURL, testAggregatorClientSecret, []string{redirectURI}, []string{"authorization_code"})
	oidcProvider.RegisterUser("https://user.example/webid#me", "testuser", "testpass")
	appClientID := oidcProvider.ClientMetadataURL([]string{redirectURI})

	reqBody := map[string]interface{}{
		"registration_type":    "authorization_code",
		"authorization_server": umaServer.URL(),
		"client_id":            appClientID,
	}
	body, _ := json.Marshal(reqBody)

	req, err := http.NewRequest("POST", testEnv.AggregatorURL+"/registration", bytes.NewBuffer(body))
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
	startClientID := start.AggregatorClientID

	authReq, err := http.NewRequest("GET", oidcProvider.URL()+"/authorize", nil)
	if err != nil {
		t.Fatalf("Failed to create authorize request: %v", err)
	}

	q := authReq.URL.Query()
	q.Set("response_type", "code")
	q.Set("client_id", startClientID)
	q.Set("redirect_uri", redirectURI)
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
		"redirect_uri":      redirectURI,
		"state":             state,
	}
	finishJSON, _ := json.Marshal(finishBody)

	finishReq, err := http.NewRequest("POST", testEnv.AggregatorURL+"/registration", bytes.NewBuffer(finishJSON))
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
	oidcProvider, err := mocks.NewOIDCProvider()
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}
	defer oidcProvider.Close()

	ownerWebID := "https://owner.example/webid#me"
	authToken := createAuthToken(t, oidcProvider, ownerWebID)

	umaServer := mocks.NewUMAAuthorizationServer()

	defer umaServer.Close()

	redirectURI := "https://app.example/callback"
	appClientID := oidcProvider.ClientMetadataURL([]string{redirectURI})

	reqBody := map[string]interface{}{
		"registration_type":    "authorization_code",
		"authorization_server": umaServer.URL(),
		"client_id":            appClientID,
	}
	body, _ := json.Marshal(reqBody)

	req, err := http.NewRequest("POST", testEnv.AggregatorURL+"/registration", bytes.NewBuffer(body))
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
		"redirect_uri":      "https://app.example/callback",
		"state":             "invalid-state-12345",
	}
	finishJSON, _ := json.Marshal(finishBody)

	finishReq, err := http.NewRequest("POST", testEnv.AggregatorURL+"/registration", bytes.NewBuffer(finishJSON))
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
	oidcProvider, err := mocks.NewOIDCProvider()
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}
	defer oidcProvider.Close()

	ownerWebID := "https://owner.example/webid#me"
	authToken := createAuthToken(t, oidcProvider, ownerWebID)

	umaServer := mocks.NewUMAAuthorizationServer()

	defer umaServer.Close()

	redirectURI := "https://app.example/callback"
	appClientID := oidcProvider.ClientMetadataURL([]string{redirectURI})

	reqBody := map[string]interface{}{
		"registration_type":    "authorization_code",
		"authorization_server": umaServer.URL(),
		"client_id":            appClientID,
	}
	body, _ := json.Marshal(reqBody)

	req, err := http.NewRequest("POST", testEnv.AggregatorURL+"/registration", bytes.NewBuffer(body))
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

	finishReq, err := http.NewRequest("POST", testEnv.AggregatorURL+"/registration", bytes.NewBuffer(finishJSON))
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
	oidcProvider, err := mocks.NewOIDCProvider()
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}
	defer oidcProvider.Close()

	// Create auth token for the owner
	ownerWebID := "https://owner.example/webid#me"
	authToken := createAuthToken(t, oidcProvider, ownerWebID)

	umaServer := mocks.NewUMAAuthorizationServer()
	defer umaServer.Close()

	// The WebID that the aggregator will act as (hosted by mock OIDC provider)
	targetWebID := oidcProvider.URL() + "/webid#me"

	// Client credentials for the target WebID
	targetClientID := "user-client-id"
	targetClientSecret := "user-client-secret"

	oidcProvider.RegisterClient(targetClientID, targetClientSecret, []string{}, []string{"client_credentials"})
	oidcProvider.RegisterUser(targetWebID, "alice@example.org", "s3cr3t-password")

	reqBody := map[string]interface{}{
		"registration_type":    "client_credentials",
		"authorization_server": umaServer.URL(),
		"webid":                targetWebID,
		"client_id":            targetClientID,
		"client_secret":        targetClientSecret,
	}
	body, _ := json.Marshal(reqBody)

	req, err := http.NewRequest("POST", testEnv.AggregatorURL+"/registration", bytes.NewBuffer(body))
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
	oidcProvider, err := mocks.NewOIDCProvider()
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}
	defer oidcProvider.Close()

	ownerWebID := "https://owner.example/webid#me"
	authToken := createAuthToken(t, oidcProvider, ownerWebID)

	umaServer := mocks.NewUMAAuthorizationServer()

	defer umaServer.Close()

	webID := oidcProvider.URL() + "/webid#me"

	reqBody := map[string]interface{}{
		"registration_type":    "client_credentials",
		"authorization_server": umaServer.URL(),
		"webid":                webID,
		"client_id":            "alice@example.org",
		"client_secret":        "wrong-password",
	}
	body, _ := json.Marshal(reqBody)

	req, err := http.NewRequest("POST", testEnv.AggregatorURL+"/registration", bytes.NewBuffer(body))
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

func TestRegistration_TokenUpdate_ClientCredentials(t *testing.T) {
	oidcProvider, err := mocks.NewOIDCProvider()
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}
	defer oidcProvider.Close()

	ownerWebID := "https://owner.example/webid#me"
	authToken := createAuthToken(t, oidcProvider, ownerWebID)

	umaServer := mocks.NewUMAAuthorizationServer()
	defer umaServer.Close()

	targetWebID := oidcProvider.URL() + "/webid#me"

	initialClientID := "user-client-id"
	initialClientSecret := "user-client-secret"
	oidcProvider.RegisterClient(initialClientID, initialClientSecret, []string{}, []string{"client_credentials"})
	oidcProvider.RegisterUser(targetWebID, "alice@example.org", "s3cr3t-password")

	createBody := map[string]interface{}{
		"registration_type":    "client_credentials",
		"authorization_server": umaServer.URL(),
		"webid":                targetWebID,
		"client_id":            initialClientID,
		"client_secret":        initialClientSecret,
	}
	body, _ := json.Marshal(createBody)

	client := &http.Client{}
	createReq, err := http.NewRequest("POST", testEnv.AggregatorURL+"/registration", bytes.NewBuffer(body))
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

	updatedClientID := "user-client-id-updated"
	updatedClientSecret := "user-client-secret-updated"
	oidcProvider.RegisterClient(updatedClientID, updatedClientSecret, []string{}, []string{"client_credentials"})

	updateBody := map[string]interface{}{
		"registration_type":    "client_credentials",
		"authorization_server": umaServer.URL(),
		"webid":                targetWebID,
		"client_id":            updatedClientID,
		"client_secret":        updatedClientSecret,
		"aggregator_id":        aggregatorID,
	}
	updateJSON, _ := json.Marshal(updateBody)

	updateReq, err := http.NewRequest("POST", testEnv.AggregatorURL+"/registration", bytes.NewBuffer(updateJSON))
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

func TestRegistration_DeviceCode(t *testing.T) {
	t.Skip("device_code flow not yet specified")
}

func TestRegistration_TokenUpdate_Provision(t *testing.T) {
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

	req, err := http.NewRequest("POST", testEnv.AggregatorURL+"/registration", bytes.NewBuffer(body))
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
}

func TestRegistration_TokenUpdate_AuthorizationCode(t *testing.T) {
	oidcProvider, err := mocks.NewOIDCProvider()
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}
	defer oidcProvider.Close()

	ownerWebID := "https://owner.example/webid#me"
	authToken := createAuthToken(t, oidcProvider, ownerWebID)

	umaServer := mocks.NewUMAAuthorizationServer()
	defer umaServer.Close()

	redirectURI := "https://app.example/callback"
	oidcProvider.RegisterClient(testAggregatorClientIDURL, testAggregatorClientSecret, []string{redirectURI}, []string{"authorization_code"})
	appClientID := oidcProvider.ClientMetadataURL([]string{redirectURI})

	createBody := map[string]interface{}{
		"registration_type":    "authorization_code",
		"authorization_server": umaServer.URL(),
		"client_id":            appClientID,
	}
	body, _ := json.Marshal(createBody)

	client := &http.Client{}
	startReq, err := http.NewRequest("POST", testEnv.AggregatorURL+"/registration", bytes.NewBuffer(body))
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
	q.Set("redirect_uri", redirectURI)
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
		"redirect_uri":      redirectURI,
		"state":             state,
	}
	finishJSON, _ := json.Marshal(finishBody)

	finishReq, err := http.NewRequest("POST", testEnv.AggregatorURL+"/registration", bytes.NewBuffer(finishJSON))
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

	updateStartBody := map[string]interface{}{
		"registration_type":    "authorization_code",
		"authorization_server": umaServer.URL(),
		"client_id":            appClientID,
		"aggregator_id":        aggregatorID,
	}
	updateStartJSON, _ := json.Marshal(updateStartBody)

	updateStartReq, err := http.NewRequest("POST", testEnv.AggregatorURL+"/registration", bytes.NewBuffer(updateStartJSON))
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
	q.Set("redirect_uri", redirectURI)
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
		"redirect_uri":      redirectURI,
		"state":             updateState,
	}
	updateFinishJSON, _ := json.Marshal(updateFinishBody)

	updateFinishReq, err := http.NewRequest("POST", testEnv.AggregatorURL+"/registration", bytes.NewBuffer(updateFinishJSON))
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

func TestRegistration_Delete_Provision(t *testing.T) {
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
}

func TestRegistration_Delete_ClientCredentials(t *testing.T) {
	oidcProvider, err := mocks.NewOIDCProvider()
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}
	defer oidcProvider.Close()

	ownerWebID := "https://owner.example/webid#me"
	authToken := createAuthToken(t, oidcProvider, ownerWebID)

	umaServer := mocks.NewUMAAuthorizationServer()
	defer umaServer.Close()

	aggregatorID := createAggregatorViaClientCredentials(t, oidcProvider, authToken, umaServer.URL())
	deleteAggregator(t, aggregatorID, authToken)
	t.Logf("Successfully deleted client_credentials aggregator %s", aggregatorID)
}

func TestRegistration_Delete_AuthorizationCode(t *testing.T) {
	oidcProvider, err := mocks.NewOIDCProvider()
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}
	defer oidcProvider.Close()

	ownerWebID := "https://owner.example/webid#me"
	authToken := createAuthToken(t, oidcProvider, ownerWebID)

	umaServer := mocks.NewUMAAuthorizationServer()
	defer umaServer.Close()

	aggregatorID := createAggregatorViaAuthorizationCode(t, oidcProvider, authToken, umaServer.URL())
	deleteAggregator(t, aggregatorID, authToken)
	t.Logf("Successfully deleted authorization_code aggregator %s", aggregatorID)
}

func TestRegistration_Delete_NotFound(t *testing.T) {
	oidcProvider, err := mocks.NewOIDCProvider()
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}
	defer oidcProvider.Close()

	ownerWebID := "https://owner.example/webid#me"
	authToken := createAuthToken(t, oidcProvider, ownerWebID)

	deleteBody := map[string]interface{}{
		"aggregator_id": "non-existent-aggregator-id-12345",
	}
	deleteJSON, _ := json.Marshal(deleteBody)

	deleteReq, err := http.NewRequest("DELETE", testEnv.AggregatorURL+"/registration", bytes.NewBuffer(deleteJSON))
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
	oidcProvider, err := mocks.NewOIDCProvider()
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}
	defer oidcProvider.Close()

	ownerWebID := "https://owner.example/webid#me"
	ownerToken := createAuthToken(t, oidcProvider, ownerWebID)

	umaServer := mocks.NewUMAAuthorizationServer()
	defer umaServer.Close()

	aggregatorID := createAggregatorViaClientCredentials(t, oidcProvider, ownerToken, umaServer.URL())

	otherProvider, err := mocks.NewOIDCProvider()
	if err != nil {
		t.Fatalf("Failed to create second OIDC provider: %v", err)
	}
	defer otherProvider.Close()
	otherToken := createAuthToken(t, otherProvider, "https://other.example/webid#me")

	deleteBody := map[string]interface{}{
		"aggregator_id": aggregatorID,
	}
	deleteJSON, _ := json.Marshal(deleteBody)

	deleteReq, err := http.NewRequest("DELETE", testEnv.AggregatorURL+"/registration", bytes.NewBuffer(deleteJSON))
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

	req, err := http.NewRequest("POST", testEnv.AggregatorURL+"/registration", bytes.NewBuffer(body))
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
	oidcProvider, err := mocks.NewOIDCProvider()
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}
	defer oidcProvider.Close()

	ownerWebID := "https://owner.example/webid#me"
	authToken := createAuthToken(t, oidcProvider, ownerWebID)

	reqBody := map[string]interface{}{
		"registration_type": "unsupported_type",
	}
	body, _ := json.Marshal(reqBody)

	req, err := http.NewRequest("POST", testEnv.AggregatorURL+"/registration", bytes.NewBuffer(body))
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
			oidcProvider, err := mocks.NewOIDCProvider()
			if err != nil {
				t.Fatalf("Failed to create OIDC provider: %v", err)
			}
			defer oidcProvider.Close()

			ownerWebID := "https://owner.example/webid#me"
			authToken := createAuthToken(t, oidcProvider, ownerWebID)

			req, err := http.NewRequest("POST", testEnv.AggregatorURL+"/registration", bytes.NewBufferString(tc.body))
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
