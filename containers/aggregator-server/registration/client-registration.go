package registration

import (
	"aggregator/model"
	"aggregator/oidc"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/google/uuid"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func registerAggregatorClient(
	ctx context.Context,
	oidcConfig *model.OIDCConfig,
	additionalGrantTypes []string,
) (string, string, string, error) {
	// Create registration request
	aggregatorID := uuid.New().String()

	registrationReq := map[string]any{
		"client_name":                aggregatorID,
		"grant_types":                append(additionalGrantTypes, "client_credentials"),
		"token_endpoint_auth_method": "client_secret_basic",
		"scope":                      "openid profile offline_access",
	}

	payload, err := json.Marshal(registrationReq)
	if err != nil {
		return "", "", "", fmt.Errorf("marshal registration payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, oidcConfig.RegistrationEndpoint, bytes.NewReader(payload))
	if err != nil {
		return "", "", "", fmt.Errorf("build registration request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Add Server Service Account Token
	token, err := oidc.FetchServiceAccountToken(ctx, oidcConfig.TokenEndpoint, model.OIDCClientId, model.OIDCClientSecret)
	if err != nil {
		return "", "", "", fmt.Errorf("fetch service account token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	// Do registration request
	resp, err := model.HttpClient.Do(req)
	if err != nil {
		return "", "", "", fmt.Errorf("execute dynamic client registration request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", "", fmt.Errorf("read registration response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return "", "", "", fmt.Errorf("registration failed (status %d): %s", resp.StatusCode, body)
	}

	// Parse credentials from response
	var result struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", "", "", fmt.Errorf("parse registration response: %w", err)
	}

	err = storeClientCredentials(aggregatorID, result.ClientID, result.ClientSecret)
	if err != nil {
		return "", "", "", fmt.Errorf("store client credentials: %w", err)
	}

	return aggregatorID, result.ClientID, result.ClientSecret, nil
}

func storeClientCredentials(aggregatorID string, clientID string, clientSecret string) error {
	_, err := model.Clientset.CoreV1().Secrets(model.Namespace).Create(context.Background(), &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("client-%s", aggregatorID),
		},
		Data: map[string][]byte{
			"client_id":     []byte(clientID),
			"client_secret": []byte(clientSecret),
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create client secret: %w", err)
	}

	return nil
}

func getClientCredentials(aggregatorID string) (string, string, error) {
	secret, err := model.Clientset.CoreV1().Secrets(model.Namespace).Get(
		context.Background(),
		fmt.Sprintf("client-%s", aggregatorID), metav1.GetOptions{},
	)
	if err != nil {
		return "", "", fmt.Errorf("get client secret: %w", err)
	}

	clientIDBytes, ok := secret.Data["client_id"]
	if !ok {
		return "", "", fmt.Errorf("client_id not found in secret")
	}
	clientSecretBytes, ok := secret.Data["client_secret"]
	if !ok {
		return "", "", fmt.Errorf("client_secret not found in secret")
	}

	return string(clientIDBytes), string(clientSecretBytes), nil
}
