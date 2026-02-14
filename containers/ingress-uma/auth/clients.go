package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"ingress-uma/signing"
)

type rsClient struct {
	ClientID        string
	ClientSecret    string
	PAT             string
	PATRefreshToken string
	PATExpiresAt    time.Time
}

type registrationRequest struct {
	Issuer          string `json:"issuer"`
	ClientID        string `json:"client_id"`
	ClientSecret    string `json:"client_secret"`
	PAT             string `json:"pat,omitempty"`
	PATExpiresIn    int    `json:"pat_expires_in,omitempty"`
	PATRefreshToken string `json:"pat_refresh_token,omitempty"`
}

type patTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

var (
	rsClientsMu sync.RWMutex
	rsClients   = make(map[string]*rsClient)
)

func HandleRegistrationRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload registrationRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	payload.Issuer = strings.TrimSpace(payload.Issuer)
	payload.ClientID = strings.TrimSpace(payload.ClientID)
	payload.ClientSecret = strings.TrimSpace(payload.ClientSecret)

	if payload.Issuer == "" || payload.ClientID == "" || payload.ClientSecret == "" {
		http.Error(w, "Missing required fields: issuer, client_id, client_secret", http.StatusBadRequest)
		return
	}

	entry := &rsClient{
		ClientID:     payload.ClientID,
		ClientSecret: payload.ClientSecret,
	}
	if strings.TrimSpace(payload.PAT) != "" {
		entry.PAT = strings.TrimSpace(payload.PAT)
		entry.PATRefreshToken = strings.TrimSpace(payload.PATRefreshToken)
		if payload.PATExpiresIn > 0 {
			entry.PATExpiresAt = time.Now().Add(time.Duration(payload.PATExpiresIn) * time.Second)
		}
	}

	rsClientsMu.Lock()
	rsClients[payload.Issuer] = entry
	rsClientsMu.Unlock()

	w.WriteHeader(http.StatusCreated)
}

func doProtectionRequest(req *http.Request, issuer string) (*http.Response, error) {
	client, ok := getRSClient(issuer)
	// If no client registered, do normal signed request
	if !ok {
		return signing.DoSignedRequest(req)
	}

	pat, err := ensurePAT(issuer, client)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+pat)
	httpClient := &http.Client{Timeout: 10 * time.Second}
	return httpClient.Do(req)
}

func getRSClient(issuer string) (*rsClient, bool) {
	rsClientsMu.RLock()
	defer rsClientsMu.RUnlock()
	client, ok := rsClients[issuer]
	return client, ok
}

func ensurePAT(issuer string, client *rsClient) (string, error) {
	if client == nil {
		return "", fmt.Errorf("no RS client registered for issuer")
	}

	if client.PAT != "" {
		if client.PATExpiresAt.IsZero() || time.Until(client.PATExpiresAt) > 30*time.Second {
			return client.PAT, nil
		}
	}

	cfg, err := fetchUmaConfig(issuer)
	if err != nil {
		return "", fmt.Errorf("failed to fetch UMA config: %w", err)
	}
	if strings.TrimSpace(cfg.TokenEndpoint) == "" {
		return "", fmt.Errorf("UMA token endpoint missing from config")
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", "uma_protection")

	req, err := http.NewRequest(http.MethodPost, cfg.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to build PAT request: %w", err)
	}
	req.SetBasicAuth(client.ClientID, client.ClientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("PAT request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("PAT request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var pat patTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&pat); err != nil {
		return "", fmt.Errorf("failed to decode PAT response: %w", err)
	}
	if strings.TrimSpace(pat.AccessToken) == "" {
		return "", fmt.Errorf("PAT response missing access_token")
	}

	rsClientsMu.Lock()
	client.PAT = pat.AccessToken
	client.PATRefreshToken = strings.TrimSpace(pat.RefreshToken)
	if pat.ExpiresIn > 0 {
		client.PATExpiresAt = time.Now().Add(time.Duration(pat.ExpiresIn) * time.Second)
	} else {
		client.PATExpiresAt = time.Time{}
	}
	rsClientsMu.Unlock()

	return pat.AccessToken, nil
}
