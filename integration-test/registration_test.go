package integration_test

import (
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
	t.Log("Starting TestRegistration_None_Create")

	aggregatorID := createAggregatorViaNone(t)
	t.Logf("Created aggregator with ID: %s", aggregatorID)

	defer func() {
		t.Logf("Deleting aggregator with ID: %s", aggregatorID)
		deleteAggregator(t, aggregatorID, "")
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	t.Log("Waiting for deployment to become ready...")
	waitForDeploymentReady(t, ctx, map[string]string{
		"app.kubernetes.io/name":      "aggregator-instance",
		"agg.knows.idlab.ugent.be/id": aggregatorID,
	})
	t.Log("Deployment reported ready")

	baseURL := fmt.Sprintf("%s/%s", Env.AggregatorServerURL, aggregatorID)
	t.Logf("Polling aggregator endpoint: %s", baseURL)

	checkCtx, checkCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer checkCancel()

	attempt := 0
	for {
		select {
		case <-checkCtx.Done():
			t.Fatalf("Timed out waiting for none aggregator description: %v", checkCtx.Err())
		default:
			attempt++
			t.Logf("HTTP attempt %d → GET %s", attempt, baseURL)

			resp, err := http.Get(baseURL)
			if err != nil {
				t.Logf("Request failed: %v", err)
			} else {
				t.Logf("Received status: %d", resp.StatusCode)
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					t.Log("Aggregator responded with 200 OK")
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
	if _, err := Env.KubeClient.AppsV1().Deployments(Env.Namespace).Get(ctx, egressUMAName, metav1.GetOptions{}); err == nil {
		t.Fatal("Expected no egress-uma deployment for none registration type")
	} else if !apierrors.IsNotFound(err) {
		t.Fatalf("Failed to check egress-uma deployment: %v", err)
	}

	// Build FnO Turtle description
	source := "http://example.org"

	// Get transformation catalog from server description
	serverResp, err := http.Get(Env.AggregatorServerURL)
	if err != nil {
		t.Fatalf("Failed to fetch server description: %v", err)
	}
	defer serverResp.Body.Close()

	var serverDesc map[string]interface{}
	json.NewDecoder(serverResp.Body).Decode(&serverDesc)
	transformationsCatalog := serverDesc["transformation_catalog"].(string) + "#"

	baseURL := Env.AggregatorServerURL + "/" + aggregatorID + "/"

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

	servicesURL := fmt.Sprintf("%s/%s%s", Env.AggregatorServerURL, aggregatorID, Env.ServiceCollectionPath)
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

	req, err := http.NewRequest("DELETE", Env.AggregatorServerURL+Env.RegistrationPath, bytes.NewBuffer(deleteJSON))
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
	ownerWebID := "https://owner.example/webid#me"
	authToken := createAuthToken(t, Env.OIDCServer, ownerWebID, true)

	redirectURI := "https://app.example/callback"
	appClientID := Env.OIDCServer.ClientMetadataURL([]string{redirectURI})

	reqBody := map[string]interface{}{
		"registration_type":    "authorization_code",
		"authorization_server": Env.UMAServer.URL(),
		"client_id":            appClientID,
	}
	body, _ := json.Marshal(reqBody)

	req, err := http.NewRequest("POST", Env.AggregatorServerURL+Env.RegistrationPath, bytes.NewBuffer(body))
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

	if start.AggregatorClientID != Env.AggregatorServerURL+Env.ClientIDPath {
		t.Errorf("Expected aggregator_client_id %s, got %s", Env.AggregatorServerURL+Env.ClientIDPath, start.AggregatorClientID)
	}
	if start.CodeChallengeMethod != "S256" {
		t.Errorf("Expected code_challenge_method S256, got %s", start.CodeChallengeMethod)
	}

	t.Logf("Authorization code flow started: aggregator_client_id=%s, state=%s", start.AggregatorClientID, start.State)
}

func TestRegistration_AuthorizationCode_Finish_Solid(t *testing.T) {
	ownerWebID := "https://owner.example/webid#me"
	authToken := createAuthToken(t, Env.OIDCServer, ownerWebID, true)

	redirectURI := "https://app.example/callback"

	Env.OIDCServer.RegisterClient(Env.AggregatorServerURL+Env.RegistrationPath, "", []string{redirectURI}, []string{"authorization_code"})
	Env.OIDCServer.RegisterUser("https://user.example/webid#me", "testuser", "testpass")
	appClientID := Env.OIDCServer.ClientMetadataURL([]string{redirectURI})

	reqBody := map[string]interface{}{
		"registration_type":    "authorization_code",
		"authorization_server": Env.UMAServer.URL(),
		"client_id":            appClientID,
	}
	body, _ := json.Marshal(reqBody)

	req, err := http.NewRequest("POST", Env.AggregatorServerURL+Env.RegistrationPath, bytes.NewBuffer(body))
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

	authReq, err := http.NewRequest("GET", Env.OIDCServer.URL()+"/authorize", nil)
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

	finishReq, err := http.NewRequest("POST", Env.AggregatorServerURL+Env.RegistrationPath, bytes.NewBuffer(finishJSON))
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
