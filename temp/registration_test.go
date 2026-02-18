package integration_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"aggregator-integration-test/mocks"
)

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
	updateProvisionConfig(t, testProvisionClientID, testProvisionClientSecret, targetWebID, oidcProvider.URL(), umaServer.URL())

	reqBody := map[string]interface{}{
		"registration_type":    "provision",
		"authorization_server": umaServer.URL(),
	}
	body, _ := json.Marshal(reqBody)

	req, err := http.NewRequest("POST", testEnv.AggregatorServerURL+"/registration", bytes.NewBuffer(body))
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
}

func TestRegistration_Provision_ReRegisterOnClientURIConflict(t *testing.T) {
	oidcProvider, err := mocks.NewOIDCProvider()
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}
	defer oidcProvider.Close()

	ownerWebID := "https://owner.example/webid#me"
	authToken := createAuthToken(t, oidcProvider, ownerWebID)

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
	updateProvisionConfig(t, validClientID, "wrong-secret", targetWebID, oidcProvider.URL(), umaServer.URL())

	reqBody := map[string]interface{}{
		"registration_type": "provision",
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

	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusBadGateway {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected 401/403/502 for invalid credentials, got %d: %s", resp.StatusCode, string(bodyBytes))
	}

	t.Logf("Provision correctly rejected invalid credentials with status %d", resp.StatusCode)
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

	// Client credentials for the target WebID
	targetClientID := "user-client-id"
	targetClientSecret := "user-client-secret"

	oidcProvider.RegisterClient(targetClientID, targetClientSecret, []string{}, []string{"client_credentials"})

	reqBody := map[string]interface{}{
		"registration_type":    "client_credentials",
		"authorization_server": umaServer.URL(),
		"client_id":            targetClientID,
		"client_secret":        targetClientSecret,
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

	reqBody := map[string]interface{}{
		"registration_type":    "client_credentials",
		"authorization_server": umaServer.URL(),
		"client_id":            "alice@example.org",
		"client_secret":        "wrong-password",
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

	initialClientID := "user-client-id"
	initialClientSecret := "user-client-secret"
	oidcProvider.RegisterClient(initialClientID, initialClientSecret, []string{}, []string{"client_credentials"})

	createBody := map[string]interface{}{
		"registration_type":    "client_credentials",
		"authorization_server": umaServer.URL(),
		"client_id":            initialClientID,
		"client_secret":        initialClientSecret,
	}
	body, _ := json.Marshal(createBody)

	client := &http.Client{}
	createReq, err := http.NewRequest("POST", testEnv.AggregatorServerURL+"/registration", bytes.NewBuffer(body))
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
		"client_id":            updatedClientID,
		"client_secret":        updatedClientSecret,
		"aggregator_id":        aggregatorID,
	}
	updateJSON, _ := json.Marshal(updateBody)

	updateReq, err := http.NewRequest("POST", testEnv.AggregatorServerURL+"/registration", bytes.NewBuffer(updateJSON))
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
}

func TestRegistration_TokenUpdate_None(t *testing.T) {
	oidcProvider, err := mocks.NewOIDCProvider()
	if err != nil {
		t.Fatalf("Failed to create OIDC provider: %v", err)
	}
	defer oidcProvider.Close()

	ownerWebID := oidcProvider.URL() + "/webid#me"
	authToken := createAuthToken(t, oidcProvider, ownerWebID)

	aggregatorID := createAggregatorViaNone(t, authToken)
	defer deleteAggregator(t, aggregatorID, authToken)

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
	req.Header.Set("Authorization", "Bearer "+authToken)

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
			oidcProvider, err := mocks.NewOIDCProvider()
			if err != nil {
				t.Fatalf("Failed to create OIDC provider: %v", err)
			}
			defer oidcProvider.Close()

			ownerWebID := "https://owner.example/webid#me"
			authToken := createAuthToken(t, oidcProvider, ownerWebID)

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
