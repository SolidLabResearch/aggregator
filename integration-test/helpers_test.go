package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"aggregator-integration-test/mocks"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"
)

type authCodeStartResponse struct {
	AggregatorClientID  string `json:"aggregator_client_id"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	State               string `json:"state"`
}

// Helper function to create a valid authentication token for tests.
func createAuthToken(t *testing.T, oidcProvider *mocks.OIDCProvider, webID string) string {
	t.Helper()

	// The mock provider returns the configured issuer (defaults to oidc.local).
	// The WebID uses the provider issuer base.
	mockWebID := oidcProvider.URL() + "/webid#me"

	// Create a JWT token with the WebID claim.
	token, err := oidcProvider.IssueTokenForWebID(mockWebID)
	if err != nil {
		t.Fatalf("Failed to create auth token: %v", err)
	}
	return token
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

func waitForDeploymentReady(t *testing.T, ctx context.Context, namespace, name string) {
	t.Helper()

	labelSelector := fmt.Sprintf("app=%s", name)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	lastStatus := "deployment not observed yet"
	for {
		select {
		case <-ctx.Done():
			podSummary := summarizePods(ctx, namespace, labelSelector)
			t.Fatalf("Timed out waiting for %s deployment to be ready: %v (last status: %s, pods: %s)", name, ctx.Err(), lastStatus, podSummary)
		case <-ticker.C:
			deployment, err := testEnv.KubeClient.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				if apierrors.IsNotFound(err) {
					deployment, err = deploymentByLabel(ctx, namespace, labelSelector)
				}
				if err != nil {
					lastStatus = err.Error()
					continue
				}
			}

			desired := int32(1)
			if deployment.Spec.Replicas != nil {
				desired = *deployment.Spec.Replicas
			}

			if deployment.Status.ObservedGeneration < deployment.Generation {
				lastStatus = "deployment update not observed yet"
				continue
			}
			if deployment.Status.UpdatedReplicas < desired {
				lastStatus = fmt.Sprintf("updated replicas %d/%d", deployment.Status.UpdatedReplicas, desired)
				continue
			}
			if deployment.Status.ReadyReplicas < desired {
				lastStatus = fmt.Sprintf("ready replicas %d/%d", deployment.Status.ReadyReplicas, desired)
				continue
			}
			if deployment.Status.AvailableReplicas < desired {
				lastStatus = fmt.Sprintf("available replicas %d/%d", deployment.Status.AvailableReplicas, desired)
				continue
			}

			return
		}
	}
}

func waitForDeploymentExists(t *testing.T, ctx context.Context, namespace, name string) *appsv1.Deployment {
	t.Helper()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			t.Fatalf("Timed out waiting for deployment %s: %v", name, ctx.Err())
		case <-ticker.C:
			deployment, err := testEnv.KubeClient.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
			if err == nil {
				return deployment
			}
			if !apierrors.IsNotFound(err) {
				t.Fatalf("Failed to get deployment %s: %v", name, err)
			}
		}
	}
}

func deploymentByLabel(ctx context.Context, namespace, labelSelector string) (*appsv1.Deployment, error) {
	list, err := testEnv.KubeClient.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{LabelSelector: labelSelector})
	if err != nil {
		return nil, fmt.Errorf("failed to list deployments with %s: %w", labelSelector, err)
	}
	if len(list.Items) == 0 {
		return nil, fmt.Errorf("deployment not found (label %s)", labelSelector)
	}
	if len(list.Items) > 1 {
		return nil, fmt.Errorf("multiple deployments found for label %s", labelSelector)
	}
	return &list.Items[0], nil
}

func summarizePods(ctx context.Context, namespace, labelSelector string) string {
	pods, err := testEnv.KubeClient.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: labelSelector})
	if err != nil {
		return "failed to list pods: " + err.Error()
	}
	if len(pods.Items) == 0 {
		return "no pods found"
	}

	summaries := make([]string, 0, len(pods.Items))
	for _, pod := range pods.Items {
		status := string(pod.Status.Phase)
		if pod.Status.Reason != "" {
			status += "/" + pod.Status.Reason
		}
		for _, cs := range pod.Status.ContainerStatuses {
			if cs.State.Waiting != nil && cs.State.Waiting.Reason != "" {
				status += " waiting=" + cs.State.Waiting.Reason
				break
			}
			if cs.State.Terminated != nil && cs.State.Terminated.Reason != "" {
				status += " terminated=" + cs.State.Terminated.Reason
				break
			}
		}
		summaries = append(summaries, fmt.Sprintf("%s:%s", pod.Name, status))
	}

	return strings.Join(summaries, ", ")
}

type aggregatorDescription struct {
	ID                    string `json:"id"`
	CreatedAt             string `json:"created_at"`
	LoginStatus           bool   `json:"login_status"`
	TokenExpiry           string `json:"token_expiry"`
	TransformationCatalog string `json:"transformation_catalog"`
	ServiceCollection     string `json:"service_collection"`
}

type aggregatorInstance struct {
	baseURL   string
	namespace string
	authToken string
	cleanup   func()
}

func setupAggregatorInstance(t *testing.T) aggregatorInstance {
	t.Helper()

	oidcProvider, err := mocks.NewOIDCProvider()
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}

	umaServer := mocks.NewUMAAuthorizationServer()

	ownerWebID := oidcProvider.URL() + "/webid#me"
	authToken := createAuthToken(t, oidcProvider, ownerWebID)

	aggregatorID := createAggregatorViaClientCredentials(t, oidcProvider, authToken, umaServer.URL())

	namespace := waitForAggregatorNamespace(t, ownerWebID)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	waitForDeploymentReady(t, ctx, namespace, "aggregator")
	waitForAggregatorDescriptionReady(t, fmt.Sprintf("%s/config/%s", testEnv.AggregatorURL, namespace), authToken, 60*time.Second)

	cleanup := func() {
		deleteAggregator(t, aggregatorID, authToken)
		oidcProvider.Close()
		umaServer.Close()
	}

	return aggregatorInstance{
		baseURL:   fmt.Sprintf("%s/config/%s", testEnv.AggregatorURL, namespace),
		namespace: namespace,
		authToken: authToken,
		cleanup:   cleanup,
	}
}

func waitForAggregatorNamespace(t *testing.T, ownerWebID string) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			t.Fatalf("Timed out waiting for aggregator namespace: %v", ctx.Err())
		case <-ticker.C:
			list, err := testEnv.KubeClient.CoreV1().Namespaces().List(ctx, metav1.ListOptions{
				LabelSelector: "created-by=aggregator",
			})
			if err != nil {
				continue
			}

			var latestName string
			var latestTime time.Time
			for _, ns := range list.Items {
				if ns.Annotations["owner"] != ownerWebID {
					continue
				}
				if latestName == "" || ns.CreationTimestamp.Time.After(latestTime) {
					latestName = ns.Name
					latestTime = ns.CreationTimestamp.Time
				}
			}

			if latestName != "" {
				return latestName
			}
		}
	}
}

func fetchAggregatorDescription(t *testing.T, baseURL string, authToken string) aggregatorDescription {
	t.Helper()

	waitForAggregatorDescriptionReady(t, baseURL, authToken, 60*time.Second)

	resp, bodyBytes := getWithUMA(t, strings.TrimRight(baseURL, "/"), authToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d: %s", resp.StatusCode, string(bodyBytes))
	}

	contentType := resp.Header.Get("Content-Type")
	if !containsContentType(contentType, "application/json") {
		t.Fatalf("Expected application/json content-type, got %s", contentType)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &raw); err != nil {
		t.Fatalf("Failed to decode aggregator description: %v", err)
	}
	if _, ok := raw["login_status"]; !ok {
		t.Fatal("login_status is missing")
	}
	if _, ok := raw["login_status"].(bool); !ok {
		t.Fatalf("login_status is not a boolean: %T", raw["login_status"])
	}

	var desc aggregatorDescription
	if err := json.Unmarshal(bodyBytes, &desc); err != nil {
		t.Fatalf("Failed to decode aggregator description: %v", err)
	}

	return desc
}

func waitForAggregatorDescriptionReady(t *testing.T, baseURL string, authToken string, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, bodyBytes := getWithUMA(t, strings.TrimRight(baseURL, "/"), authToken)
		if resp.StatusCode == http.StatusOK {
			return
		}
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("Expected 200 OK or 503 while waiting for description, got %d: %s", resp.StatusCode, string(bodyBytes))
		}
		time.Sleep(2 * time.Second)
	}

	t.Fatalf("Timed out waiting for aggregator description at %s", baseURL)
}

func getWithUMA(t *testing.T, url string, claimToken string) (*http.Response, []byte) {
	t.Helper()

	return doWithUMA(t, http.MethodGet, url, claimToken, nil, "")
}

func doWithUMA(t *testing.T, method, url string, claimToken string, body []byte, contentType string) (*http.Response, []byte) {
	t.Helper()

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	buildRequest := func() (*http.Request, error) {
		var reader io.Reader
		if body != nil {
			reader = bytes.NewReader(body)
		}
		req, err := http.NewRequest(method, url, reader)
		if err != nil {
			return nil, err
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		return req, nil
	}

	req, err := buildRequest()
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusUnauthorized {
		return resp, bodyBytes
	}

	asURI, ticket := parseUMAHeader(resp.Header.Get("WWW-Authenticate"))
	if (asURI == "" || ticket == "") && method != http.MethodGet {
		asURI, ticket = fetchUMAChallenge(t, url)
	}
	if asURI == "" || ticket == "" {
		return resp, bodyBytes
	}

	rpt := requestRPT(t, asURI, ticket, claimToken)

	req, err = buildRequest()
	if err != nil {
		t.Fatalf("Failed to create UMA retry request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+rpt)

	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("UMA retry request failed: %v", err)
	}
	bodyBytes, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("Failed to read UMA retry response body: %v", err)
	}

	return resp, bodyBytes
}

func parseUMAHeader(header string) (string, string) {
	if header == "" {
		return "", ""
	}

	header = strings.TrimSpace(header)
	if strings.HasPrefix(strings.ToUpper(header), "UMA") {
		header = strings.TrimSpace(header[3:])
	}

	var asURI string
	var ticket string
	parts := strings.Split(header, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "as_uri=") {
			asURI = strings.Trim(part[len("as_uri="):], `"`)
		}
		if strings.HasPrefix(part, "ticket=") {
			ticket = strings.Trim(part[len("ticket="):], `"`)
		}
	}

	return asURI, ticket
}

func requestRPT(t *testing.T, asURI, ticket, claimToken string) string {
	t.Helper()

	tokenEndpoint := fetchUMATokenEndpoint(t, asURI)

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket")
	form.Set("ticket", ticket)
	if claimToken != "" {
		form.Set("claim_token", claimToken)
		form.Set("claim_token_format", "urn:ietf:params:oauth:token-type:id_token")
	}

	resp, err := http.PostForm(tokenEndpoint, form)
	if err != nil {
		t.Fatalf("Failed to request RPT: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read RPT response: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("RPT request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var payload struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		t.Fatalf("Failed to decode RPT response: %v", err)
	}
	if payload.AccessToken == "" {
		t.Fatalf("RPT response missing access_token: %s", string(bodyBytes))
	}

	return payload.AccessToken
}

func fetchUMAChallenge(t *testing.T, url string) (string, string) {
	t.Helper()

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("Failed to create UMA challenge request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("UMA challenge request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		return "", ""
	}

	return parseUMAHeader(resp.Header.Get("WWW-Authenticate"))
}

func fetchUMATokenEndpoint(t *testing.T, asURI string) string {
	t.Helper()

	resp, err := http.Get(strings.TrimRight(asURI, "/") + "/.well-known/uma2-configuration")
	if err != nil {
		t.Fatalf("Failed to fetch UMA configuration: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("UMA configuration returned %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var cfg struct {
		TokenEndpoint string `json:"token_endpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		t.Fatalf("Failed to decode UMA configuration: %v", err)
	}
	if cfg.TokenEndpoint == "" {
		t.Fatal("UMA configuration missing token_endpoint")
	}

	return cfg.TokenEndpoint
}

func isAbsoluteURL(candidate string) bool {
	parsed, err := url.Parse(candidate)
	if err != nil {
		return false
	}
	return parsed.IsAbs()
}

// Helper function to check if a content type contains a specific type.
func containsContentType(contentType, expectedType string) bool {
	return len(contentType) > 0 && (contentType == expectedType ||
		len(contentType) > len(expectedType) && contentType[:len(expectedType)] == expectedType ||
		containsString(contentType, expectedType))
}

// Helper function to check if a string contains a substring.
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())
}

func getDynamicClient(t *testing.T) dynamic.Interface {
	t.Helper()

	kubeconfig := clientcmd.NewDefaultClientConfigLoadingRules().GetDefaultFilename()
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatalf("Failed to build kubeconfig for dynamic client: %v", err)
	}

	client, err := dynamic.NewForConfig(config)
	if err != nil {
		t.Fatalf("Failed to create dynamic client: %v", err)
	}

	return client
}

func getIngressRoute(t *testing.T, namespace, name string) *unstructured.Unstructured {
	t.Helper()

	client := getDynamicClient(t)
	ingressRouteGVR := schema.GroupVersionResource{
		Group:    "traefik.io",
		Version:  "v1alpha1",
		Resource: "ingressroutes",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	obj, err := client.Resource(ingressRouteGVR).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Failed to get IngressRoute %s: %v", name, err)
	}

	return obj
}

func ingressRouteHasMiddleware(t *testing.T, ingressRoute *unstructured.Unstructured, name string) bool {
	t.Helper()

	routes, found, err := unstructured.NestedSlice(ingressRoute.Object, "spec", "routes")
	if err != nil || !found {
		t.Fatalf("IngressRoute missing routes: %v", err)
	}

	for _, route := range routes {
		routeMap, ok := route.(map[string]interface{})
		if !ok {
			continue
		}
		middlewares, _, err := unstructured.NestedSlice(routeMap, "middlewares")
		if err != nil {
			t.Fatalf("Failed to read middlewares: %v", err)
		}
		for _, mw := range middlewares {
			mwMap, ok := mw.(map[string]interface{})
			if !ok {
				continue
			}
			if mwMap["name"] == name {
				return true
			}
		}
	}

	return false
}

func createAggregatorViaNone(t *testing.T, authToken string) string {
	t.Helper()

	createBody := map[string]interface{}{
		"registration_type": "none",
	}
	body, _ := json.Marshal(createBody)

	req, err := http.NewRequest("POST", testEnv.AggregatorURL+"/registration", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to create none request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("None request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected 201 Created for none, got %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode none response: %v", err)
	}
	aggregatorID, ok := response["aggregator_id"].(string)
	if !ok || aggregatorID == "" {
		t.Fatalf("None response missing aggregator_id")
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