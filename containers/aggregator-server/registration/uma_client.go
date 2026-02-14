package registration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

const ingressUMARegistrationURL = "http://ingress-uma.aggregator-app.svc.cluster.local/registrations"

type umaConfig struct {
	Issuer                       string `json:"issuer"`
	JwksURI                      string `json:"jwks_uri"`
	TokenEndpoint                string `json:"token_endpoint"`
	RegistrationEndpoint         string `json:"registration_endpoint"`
	ResourceRegistrationEndpoint string `json:"resource_registration_endpoint"`
	PermissionEndpoint           string `json:"permission_endpoint"`
	IntrospectionEndpoint        string `json:"introspection_endpoint"`
}

type umaClientRegistration struct {
	ClientID                string `json:"client_id"`
	ClientSecret            string `json:"client_secret"`
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method"`
}

type umaClientMetadata struct {
	ClientID  string `json:"client_id"`
	ClientURI string `json:"client_uri"`
	ID        string `json:"id"`
	URI       string `json:"uri"`
}

type umaRegistrationError struct {
	Status int
	Body   string
}

func (e *umaRegistrationError) Error() string {
	return fmt.Sprintf("UMA registration failed with status %d: %s", e.Status, e.Body)
}

type patResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

type ingressUMARegistration struct {
	Issuer          string `json:"issuer"`
	ClientID        string `json:"client_id"`
	ClientSecret    string `json:"client_secret"`
	PAT             string `json:"pat,omitempty"`
	PATExpiresIn    int    `json:"pat_expires_in,omitempty"`
	PATRefreshToken string `json:"pat_refresh_token,omitempty"`
}

func fetchUMAConfig(issuer string) (*umaConfig, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(issuer), "/")
	if trimmed == "" {
		return nil, fmt.Errorf("UMA issuer is empty")
	}

	discoveryURL := fmt.Sprintf("%s/.well-known/uma2-configuration", trimmed)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch UMA discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("UMA discovery returned status %s", resp.Status)
	}

	var cfg umaConfig
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("failed to decode UMA discovery JSON: %w", err)
	}

	if strings.TrimSpace(cfg.Issuer) == "" ||
		strings.TrimSpace(cfg.TokenEndpoint) == "" ||
		strings.TrimSpace(cfg.RegistrationEndpoint) == "" ||
		strings.TrimSpace(cfg.ResourceRegistrationEndpoint) == "" ||
		strings.TrimSpace(cfg.PermissionEndpoint) == "" ||
		strings.TrimSpace(cfg.IntrospectionEndpoint) == "" ||
		strings.TrimSpace(cfg.JwksURI) == "" {
		return nil, fmt.Errorf("UMA discovery missing required fields")
	}

	return &cfg, nil
}

func registerResourceServer(cfg *umaConfig, bearerToken string, clientName string, clientURI string) (*umaClientRegistration, error) {
	if cfg == nil || strings.TrimSpace(cfg.RegistrationEndpoint) == "" {
		return nil, fmt.Errorf("UMA registration endpoint not configured")
	}
	if strings.TrimSpace(bearerToken) == "" {
		return nil, fmt.Errorf("Bearer token is required for UMA client registration")
	}

	payload := map[string]string{}
	if strings.TrimSpace(clientName) != "" {
		payload["client_name"] = clientName
	}
	if strings.TrimSpace(clientURI) != "" {
		payload["client_uri"] = clientURI
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to encode UMA registration payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, cfg.RegistrationEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to build UMA registration request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearerToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("UMA registration request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, &umaRegistrationError{
			Status: resp.StatusCode,
			Body:   string(bodyBytes),
		}
	}

	var reg umaClientRegistration
	if err := json.NewDecoder(resp.Body).Decode(&reg); err != nil {
		return nil, fmt.Errorf("failed to decode UMA registration response: %w", err)
	}

	if strings.TrimSpace(reg.ClientID) == "" || strings.TrimSpace(reg.ClientSecret) == "" {
		return nil, fmt.Errorf("UMA registration response missing client credentials")
	}

	if reg.TokenEndpointAuthMethod != "" && reg.TokenEndpointAuthMethod != "client_secret_basic" {
		logrus.WithField("method", reg.TokenEndpointAuthMethod).
			Warn("UMA registration returned unexpected token_endpoint_auth_method")
	}

	return &reg, nil
}

func deleteResourceServer(cfg *umaConfig, bearerToken string, clientID string) error {
	if cfg == nil || strings.TrimSpace(cfg.RegistrationEndpoint) == "" {
		return fmt.Errorf("UMA registration endpoint not configured")
	}
	if strings.TrimSpace(bearerToken) == "" {
		return fmt.Errorf("Bearer token is required for UMA client deletion")
	}
	if strings.TrimSpace(clientID) == "" {
		return fmt.Errorf("Client ID is required for UMA client deletion")
	}

	base := strings.TrimRight(cfg.RegistrationEndpoint, "/")
	deleteURL := base + "/" + url.PathEscape(clientID)
	req, err := http.NewRequest(http.MethodDelete, deleteURL, nil)
	if err != nil {
		return fmt.Errorf("failed to build UMA delete request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearerToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("UMA delete request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("UMA delete failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

func findClientIDByURI(cfg *umaConfig, bearerToken string, clientURI string) (string, error) {
	if cfg == nil || strings.TrimSpace(cfg.RegistrationEndpoint) == "" {
		return "", fmt.Errorf("UMA registration endpoint not configured")
	}
	if strings.TrimSpace(bearerToken) == "" {
		return "", fmt.Errorf("Bearer token is required for UMA client lookup")
	}
	if strings.TrimSpace(clientURI) == "" {
		return "", fmt.Errorf("client_uri is required for UMA client lookup")
	}

	req, err := http.NewRequest(http.MethodGet, cfg.RegistrationEndpoint, nil)
	if err != nil {
		return "", fmt.Errorf("failed to build UMA list request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("UMA list request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("UMA list request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read UMA list response: %w", err)
	}

	var entries []map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &entries); err != nil {
		return "", fmt.Errorf("failed to parse UMA list response")
	}
	for _, entry := range entries {
		raw, ok := entry["uri"]
		if !ok {
			continue
		}
		client_uri, ok := raw.(string)
		if !ok || client_uri != clientURI {
			continue
		}

		idRaw, ok := entry["id"]
		if !ok {
			continue
		}
		clientID, ok := idRaw.(string)
		if !ok || strings.TrimSpace(clientID) == "" {
			continue
		}
		return clientID, nil
	}
	return "", fmt.Errorf("UMA list response did not include the correct client ID for URI %s", clientURI)
}

func requestPAT(tokenEndpoint string, clientID string, clientSecret string) (*patResponse, error) {
	if strings.TrimSpace(tokenEndpoint) == "" {
		return nil, fmt.Errorf("UMA token endpoint is required for PAT request")
	}
	if strings.TrimSpace(clientID) == "" || strings.TrimSpace(clientSecret) == "" {
		return nil, fmt.Errorf("UMA client credentials are required for PAT request")
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", "uma_protection")

	req, err := http.NewRequest(http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to build PAT request: %w", err)
	}
	req.SetBasicAuth(clientID, clientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("PAT request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("PAT request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var pat patResponse
	if err := json.NewDecoder(resp.Body).Decode(&pat); err != nil {
		return nil, fmt.Errorf("failed to decode PAT response: %w", err)
	}

	if strings.TrimSpace(pat.AccessToken) == "" {
		return nil, fmt.Errorf("PAT response missing access_token")
	}

	return &pat, nil
}

func registerIngressUMAClient(issuer string, clientID string, clientSecret string, pat *patResponse) error {
	if strings.TrimSpace(issuer) == "" || strings.TrimSpace(clientID) == "" || strings.TrimSpace(clientSecret) == "" {
		return fmt.Errorf("issuer and client credentials are required for ingress UMA registration")
	}

	payload := ingressUMARegistration{
		Issuer:       issuer,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}
	if pat != nil {
		payload.PAT = pat.AccessToken
		payload.PATExpiresIn = pat.ExpiresIn
		payload.PATRefreshToken = pat.RefreshToken
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to encode ingress UMA registration payload: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(ingressUMARegistrationURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to register ingress UMA client: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("ingress UMA registration failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

func ensurePATForUMA(ctx context.Context, cfg *umaConfig, bearerToken string, clientURI string) (string, string, *patResponse, error) {
	if cfg == nil {
		return "", "", nil, fmt.Errorf("UMA config is required")
	}

	storedCreds, hasStoredCreds, err := loadProvisionUMACredentials(ctx)
	if err != nil {
		return "", "", nil, err
	}

	if hasStoredCreds {
		pat, err := requestPAT(cfg.TokenEndpoint, storedCreds.ClientID, storedCreds.ClientSecret)
		if err == nil {
			return storedCreds.ClientID, storedCreds.ClientSecret, pat, nil
		}
		logrus.WithError(err).Warn("Stored UMA client credentials failed; re-registering")
	}

	umaClient, err := registerResourceServer(cfg, bearerToken, "aggregator-rs", clientURI)
	if err != nil {
		var regErr *umaRegistrationError
		if errors.As(err, &regErr) && regErr.Status == http.StatusConflict {
			logrus.WithError(err).Warn("RS already registered at UMA server; locating registration to delete")
			deleteClientID, err := findClientIDByURI(cfg, bearerToken, clientURI)
			if err != nil {
				return "", "", nil, fmt.Errorf("unable to locate UMA registration to delete: %w", err)
			}

			if err := deleteResourceServer(cfg, bearerToken, deleteClientID); err != nil {
				return "", "", nil, fmt.Errorf("unable to delete existing UMA registration: %w", err)
			}

			umaClient, err = registerResourceServer(cfg, bearerToken, "aggregator-rs", clientURI)
			if err != nil {
				return "", "", nil, fmt.Errorf("unable to re-register RS at UMA server: %w", err)
			}
		} else {
			return "", "", nil, fmt.Errorf("unable to register RS at UMA server: %w", err)
		}
	}

	if umaClient == nil {
		return "", "", nil, fmt.Errorf("UMA registration did not return client credentials")
	}

	if err := storeProvisionUMACredentials(ctx, umaClient.ClientID, umaClient.ClientSecret); err != nil {
		return "", "", nil, fmt.Errorf("unable to store UMA client credentials: %w", err)
	}

	pat, err := requestPAT(cfg.TokenEndpoint, umaClient.ClientID, umaClient.ClientSecret)
	if err != nil {
		return "", "", nil, err
	}

	return umaClient.ClientID, umaClient.ClientSecret, pat, nil
}
