package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"ingress-uma/model"
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
	log := logrus.WithField("component", "registration")

	log.Info("Received registration request")

	if r.Method != http.MethodPost {
		log.WithField("method", r.Method).
			Warn("Invalid HTTP method")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.WithError(err).Error("Failed to decode registration request body")
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.UserID == "" || req.IDToken == "" || req.AuthzServer == "" {
		log.Warn("Missing required fields: user_id, id_token or as_url")
		http.Error(w, "user_id, id_token and as_url are required", http.StatusBadRequest)
		return
	}

	log = log.WithFields(logrus.Fields{
		"user_id": req.UserID,
		"as_url":  req.AuthzServer,
	})

	log.Debug("Storing user ID token")

	mu.Lock()
	userCredentials[req.UserID] = req.IDToken
	mu.Unlock()

	reg := Registration{
		UserID:      req.UserID,
		AuthzServer: req.AuthzServer,
	}

	mu.Lock()
	_, exists := serverCredentials[reg]
	mu.Unlock()

	if exists {
		log.Info("Aggregator already registered at AS")
		w.WriteHeader(http.StatusOK)
		return
	}

	log.Info("Requesting client credentials from Authorization Server")

	serverCreds, err := requestCredentials(reg)
	if err != nil {
		log.WithError(err).Error("Failed to register client at AS")
		http.Error(w, fmt.Sprintf("Failed to register client: %v", err), http.StatusInternalServerError)
		return
	}

	mu.Lock()
	serverCredentials[reg] = serverCreds
	mu.Unlock()

	log.WithFields(logrus.Fields{
		"client_id": serverCreds.ClientID,
		"expires":   serverCreds.ExpiresAt,
	}).Info("Successfully stored client credentials")

	w.WriteHeader(http.StatusOK)
	log.Info("Registration completed successfully")
}

func GetCredentials(reg Registration) (string, string, error) {
	log := logrus.WithFields(logrus.Fields{
		"user_id":   reg.UserID,
		"as_url":    reg.AuthzServer,
		"component": "credentials",
	})

	mu.Lock()
	creds, exists := serverCredentials[reg]
	mu.Unlock()

	if !exists {
		err := fmt.Errorf("no credentials stored")
		log.Error(err)
		return "", "", err
	}

	if isExpired(creds) {
		log.Info("Client credentials expired, requesting renewal")

		newCreds, err := requestCredentials(reg)
		if err != nil {
			log.WithError(err).Error("Failed to renew client credentials")
			return "", "", err
		}

		mu.Lock()
		serverCredentials[reg] = newCreds
		mu.Unlock()

		log.WithField("expires", newCreds.ExpiresAt).
			Info("Successfully renewed client credentials")

		return newCreds.ClientID, newCreds.ClientSecret, nil
	}

	log.Debug("Using cached client credentials")

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
	log := logrus.WithFields(logrus.Fields{
		"user_id":   reg.UserID,
		"as_url":    reg.AuthzServer,
		"component": "client_registration",
	})

	log.Debug("Fetching UMA configuration")

	config, err := fetchUmaConfig(reg.AuthzServer)
	if err != nil {
		log.WithError(err).Error("Failed to fetch UMA configuration")
		return Credentials{}, err
	}

	payload := map[string]string{
		"client_uri": "http://" + ExternalHost,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		log.WithError(err).Error("Failed to marshal client registration payload")
		return Credentials{}, err
	}

	req, err := http.NewRequest("POST", config.RegistrationEndpoint, bytes.NewBuffer(body))
	if err != nil {
		log.WithError(err).Error("Failed to create registration request")
		return Credentials{}, err
	}

	idToken := userCredentials[reg.UserID]
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+idToken)

	log.WithField("endpoint", config.RegistrationEndpoint).
		Debug("Sending client registration request")

	resp, err := model.HttpClient.Do(req)
	if err != nil {
		log.WithError(err).Error("HTTP request to AS failed")
		return Credentials{}, err
	}
	defer resp.Body.Close()

	log.WithField("status_code", resp.StatusCode).
		Debug("Received response from AS")

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		err := errors.New("failed to register client with AS")
		log.WithField("status_code", resp.StatusCode).
			Error("AS returned error during client registration")
		return Credentials{}, err
	}

	var response struct {
		ClientID              string `json:"client_id"`
		ClientSecret          string `json:"client_secret"`
		ClientSecretExpiresAt int64  `json:"client_secret_expires_at,string"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		log.WithError(err).Error("Failed to decode client registration response")
		return Credentials{}, err
	}

	var expiresAt time.Time
	if response.ClientSecretExpiresAt > 0 {
		expiresAt = time.Unix(response.ClientSecretExpiresAt, 0)
	}

	log.WithFields(logrus.Fields{
		"client_id": response.ClientID,
		"expires":   expiresAt,
	}).Info("Client successfully registered at AS")

	return Credentials{
		ClientID:     response.ClientID,
		ClientSecret: response.ClientSecret,
		ExpiresAt:    expiresAt,
	}, nil
}

func getPAT(reg Registration) (string, error) {
	log := logrus.WithFields(logrus.Fields{
		"user_id":   reg.UserID,
		"as_url":    reg.AuthzServer,
		"component": "pat",
	})

	mu.Lock()
	pat, exists := patMap[reg]
	mu.Unlock()

	if exists && time.Now().Before(pat.ExpiresAt) {
		log.Debug("Using cached PAT")
		return pat.AccessToken, nil
	}

	log.Info("Requesting new PAT")

	clientID, clientSecret, err := GetCredentials(reg)
	if err != nil {
		log.WithError(err).Error("Failed to obtain client credentials for PAT")
		return "", err
	}

	config, err := fetchUmaConfig(reg.AuthzServer)
	if err != nil {
		log.WithError(err).Error("Failed to fetch UMA configuration for PAT")
		return "", err
	}

	form := "grant_type=client_credentials&scope=uma_protection"

	req, err := http.NewRequest("POST", config.TokenEndpoint, bytes.NewBufferString(form))
	if err != nil {
		log.WithError(err).Error("Failed to create PAT request")
		return "", err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	auth := clientID + ":" + clientSecret
	req.Header.Set("Authorization", "Basic "+basicAuth(auth))

	resp, err := model.HttpClient.Do(req)
	if err != nil {
		log.WithError(err).Error("PAT request failed")
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.WithField("status_code", resp.StatusCode).
			Error("AS returned error during PAT request")
		return "", errors.New("failed to obtain PAT")
	}

	var body struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		log.WithError(err).Error("Failed to decode PAT response")
		return "", err
	}

	pat = PAT{
		AccessToken: body.AccessToken,
		ExpiresAt:   time.Now().Add(time.Duration(body.ExpiresIn) * time.Second),
	}

	mu.Lock()
	patMap[reg] = pat
	mu.Unlock()

	log.WithField("expires", pat.ExpiresAt).
		Info("Successfully obtained new PAT")

	return pat.AccessToken, nil
}

func basicAuth(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}
