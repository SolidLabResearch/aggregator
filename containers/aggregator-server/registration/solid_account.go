package registration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type solidAccountControls struct {
	Controls struct {
		Password struct {
			Login string `json:"login"`
		} `json:"password"`
		Account struct {
			ClientCredentials string `json:"clientCredentials"`
		} `json:"account"`
	} `json:"controls"`
}

func deriveSolidBaseURL(idpIssuer string) (string, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(idpIssuer), "/")
	if trimmed == "" {
		return "", fmt.Errorf("IDP issuer is empty")
	}

	for _, suffix := range []string{"/idp", "/.oidc"} {
		if strings.HasSuffix(trimmed, suffix) {
			trimmed = strings.TrimSuffix(trimmed, suffix)
			break
		}
	}

	if trimmed == "" {
		return "", fmt.Errorf("invalid IDP issuer for Solid base")
	}

	return trimmed, nil
}

func fetchSolidClientCredentials(baseURL string, email string, password string, name string, webID string) (string, string, error) {
	controls, err := fetchSolidAccountControls(baseURL, "")
	if err != nil {
		return "", "", err
	}
	loginURL := strings.TrimSpace(controls.Controls.Password.Login)
	if loginURL == "" {
		return "", "", fmt.Errorf("password login endpoint missing from account controls")
	}

	authToken, err := loginSolidAccount(loginURL, email, password)
	if err != nil {
		return "", "", err
	}

	controls, err = fetchSolidAccountControls(baseURL, authToken)
	if err != nil {
		return "", "", err
	}
	credsURL := strings.TrimSpace(controls.Controls.Account.ClientCredentials)
	if credsURL == "" {
		return "", "", fmt.Errorf("client credentials endpoint missing from account controls")
	}

	return createSolidClientCredentials(credsURL, authToken, name, webID)
}

func fetchSolidAccountControls(baseURL string, authToken string) (solidAccountControls, error) {
	url := strings.TrimRight(baseURL, "/") + "/.account/"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return solidAccountControls{}, err
	}
	req.Header.Set("Accept", "application/json")
	if strings.TrimSpace(authToken) != "" {
		req.Header.Set("Authorization", "CSS-Account-Token "+authToken)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return solidAccountControls{}, fmt.Errorf("failed to fetch account controls: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return solidAccountControls{}, fmt.Errorf("account controls request failed: %s", string(bodyBytes))
	}

	var controls solidAccountControls
	if err := json.NewDecoder(resp.Body).Decode(&controls); err != nil {
		return solidAccountControls{}, fmt.Errorf("failed to decode account controls: %w", err)
	}

	return controls, nil
}

func loginSolidAccount(loginURL string, email string, password string) (string, error) {
	payload := map[string]string{
		"email":    email,
		"password": password,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, loginURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("login failed: %s", string(bodyBytes))
	}

	var response struct {
		Authorization string `json:"authorization"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", err
	}
	if strings.TrimSpace(response.Authorization) == "" {
		return "", fmt.Errorf("login response missing authorization token")
	}

	return response.Authorization, nil
}

func createSolidClientCredentials(endpoint string, authToken string, name string, webID string) (string, string, error) {
	payload := map[string]string{
		"name":  name,
		"webId": webID,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", "", err
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "CSS-Account-Token "+authToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("client credentials request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", "", fmt.Errorf("client credentials request failed: %s", string(bodyBytes))
	}

	var response struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", "", err
	}
	if strings.TrimSpace(response.ID) == "" || strings.TrimSpace(response.Secret) == "" {
		return "", "", fmt.Errorf("client credentials response missing id/secret")
	}

	return response.ID, response.Secret, nil
}
