package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type RegistrationRequest struct {
	UserID      string `json:"user_id"`
	IDToken     string `json:"id_token"`
	AuthzServer string `json:"as_url"`
}

type Registration struct {
	UserID      string
	AuthzServer string
}

type Credentials struct {
	IDToken      string
	ClientID     string
	ClientSecret string
	ExpiresAt    time.Time
}

type PAT struct {
	AccessToken string
	ExpiresAt   time.Time
}

var (
	userCredentials   = make(map[string]string)
	serverCredentials = make(map[Registration]Credentials)
	mu                sync.Mutex
	patMap            = make(map[Registration]PAT)
)

// HandleRegistrationRequest registers the aggregator as RS at the AS
func HandleRegistrationRequest(w http.ResponseWriter, r *http.Request) {
	logrus.Info("Received registration request")

	if r.Method != http.MethodPost {
		logrus.Warnf("Invalid method: %s, only POST allowed", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logrus.Errorf("Failed to decode registration request: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.UserID == "" || req.IDToken == "" || req.AuthzServer == "" {
		logrus.Warn("Missing user_id, id_token or as_url in registration request")
		http.Error(w, "user_id, id_token and as_url are required", http.StatusBadRequest)
		return
	}
	mu.Lock()
	userCredentials[req.UserID] = req.IDToken
	mu.Unlock()

	reg := Registration{
		req.UserID,
		req.AuthzServer,
	}
	mu.Lock()
	serverCreds, exists := serverCredentials[reg]
	mu.Unlock()
	if exists {
		logrus.Infof("Aggregator already registered at %s", req.AuthzServer)
		w.WriteHeader(http.StatusOK)
		return
	}

	logrus.Debugf("Processing registration for AS: %s", req.AuthzServer)

	// Request client credentials from the AS
	serverCreds, err := requestCredentials(reg)
	if err != nil {
		logrus.Errorf("Failed to request credentials from AS %s: %v", req.AuthzServer, err)
		http.Error(w, fmt.Sprintf("Failed to register client: %v", err), http.StatusInternalServerError)
		return
	}

	// Store credentials
	mu.Lock()
	serverCredentials[reg] = serverCreds
	mu.Unlock()
	logrus.Infof("Stored credentials for AS: %s", req.AuthzServer)

	// Respond with status OK
	w.WriteHeader(http.StatusOK)
	logrus.Info("Registration request handled successfully")
}

func GetCredentials(reg Registration) (string, string, error) {
	mu.Lock()
	creds, exists := serverCredentials[reg]
	mu.Unlock()

	if !exists {
		return "", "", fmt.Errorf("No credentials stored for user %s at %s", reg.UserID, reg.AuthzServer)
	}

	// If not present or expired → renew
	if isExpired(creds) {
		newCreds, err := requestCredentials(reg)
		if err != nil {
			return "", "", err
		}

		mu.Lock()
		serverCredentials[reg] = newCreds
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

func requestCredentials(reg Registration) (Credentials, error) {
	config, err := fetchUmaConfig(reg.AuthzServer)
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

	idToken := userCredentials[reg.UserID]
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+idToken)

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
		ClientSecretExpiresAt int64  `json:"client_secret_expires_at,string"`
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

func getPAT(reg Registration) (string, error) {
	mu.Lock()
	pat, exists := patMap[reg]
	mu.Unlock()

	if exists && time.Now().Before(pat.ExpiresAt) {
		return pat.AccessToken, nil
	}

	clientID, clientSecret, err := GetCredentials(reg)
	if err != nil {
		return "", err
	}

	config, err := fetchUmaConfig(reg.AuthzServer)
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

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
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
	patMap[reg] = pat
	mu.Unlock()

	return pat.AccessToken, nil
}

func basicAuth(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}
