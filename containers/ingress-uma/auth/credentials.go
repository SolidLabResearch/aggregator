package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"
)

type Credentials struct {
	ClientID     string
	ClientSecret string
	ExpiresAt    time.Time
}

type PAT struct {
	AccessToken string
	ExpiresAt   time.Time
}

var (
	credentialsMap = make(map[string]Credentials)
	mu             sync.Mutex
	patMap         = make(map[string]PAT)
)

func GetCredentials(issuer string) (string, string, error) {
	mu.Lock()
	creds, exists := credentialsMap[issuer]
	mu.Unlock()

	// If not present or expired → renew
	if !exists || isExpired(creds) {
		newCreds, err := requestCredentials(issuer)
		if err != nil {
			return "", "", err
		}

		mu.Lock()
		credentialsMap[issuer] = newCreds
		mu.Unlock()

		return newCreds.ClientID, newCreds.ClientSecret, nil
	}

	return creds.ClientID, creds.ClientSecret, nil
}

func isExpired(creds Credentials) bool {
	// Some AS return "0" meaning "never expires"
	if creds.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(creds.ExpiresAt)
}

func requestCredentials(issuer string) (Credentials, error) {
	config, err := fetchUmaConfig(issuer)
	if err != nil {
		return Credentials{}, err
	}

	payload := map[string]string{
		"client_uri": "http://" + ExternalHost,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return Credentials{}, err
	}

	req, err := http.NewRequest("POST", config.RegistrationEndpoint, bytes.NewBuffer(body))
	if err != nil {
		return Credentials{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Credentials{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return Credentials{}, errors.New("failed to register client with AS")
	}

	var response struct {
		ClientID              string `json:"client_id"`
		ClientSecret          string `json:"client_secret"`
		ClientSecretExpiresAt int64  `json:"client_secret_expires_at"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return Credentials{}, err
	}

	var expiresAt time.Time
	if response.ClientSecretExpiresAt > 0 {
		expiresAt = time.Unix(response.ClientSecretExpiresAt, 0)
	}

	return Credentials{
		ClientID:     response.ClientID,
		ClientSecret: response.ClientSecret,
		ExpiresAt:    expiresAt,
	}, nil
}

func getPAT(issuer string) (string, error) {
	mu.Lock()
	pat, exists := patMap[issuer]
	mu.Unlock()

	if exists && time.Now().Before(pat.ExpiresAt) {
		return pat.AccessToken, nil
	}

	clientID, clientSecret, err := GetCredentials(issuer)
	if err != nil {
		return "", err
	}

	config, err := fetchUmaConfig(issuer)
	if err != nil {
		return "", err
	}

	form := "grant_type=client_credentials&scope=uma_protection"

	req, err := http.NewRequest("POST", config.TokenEndpoint, bytes.NewBufferString(form))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	auth := clientID + ":" + clientSecret
	req.Header.Set("Authorization", "Basic "+basicAuth(auth))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errors.New("failed to obtain PAT")
	}

	var body struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}

	pat = PAT{
		AccessToken: body.AccessToken,
		ExpiresAt:   time.Now().Add(time.Duration(body.ExpiresIn) * time.Second),
	}

	mu.Lock()
	patMap[issuer] = pat
	mu.Unlock()

	return pat.AccessToken, nil
}

func basicAuth(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func DoSignedRequest(req *http.Request, issuer string) (*http.Response, error) {
	pat, err := getPAT(issuer)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+pat)

	return http.DefaultClient.Do(req)
}
