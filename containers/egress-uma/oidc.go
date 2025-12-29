package main

import (
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

// createClaimToken returns a valid access token, refreshing if necessary
func createClaimToken() (string, error) {
	TokenMutex.Lock()
	defer TokenMutex.Unlock()

	// Check if token is valid for at least 30 seconds
	if AccessToken != "" && time.Until(TokenExpiry) > 30*time.Second {
		return AccessToken, nil
	}

	if RefreshToken == "" {
		return "", errors.New("no refresh token available")
	}

	// Request a new access token using the refresh token
	newToken, expiresIn, err := refreshAccessToken(RefreshToken)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get valid access token")
	}

	AccessToken = newToken
	TokenExpiry = time.Now().Add(time.Duration(expiresIn) * time.Second)

	return AccessToken, nil
}

// initAccessToken initializes the access token once at startup
func initAccessToken() error {
	logrus.Info("Acquiring inital access token...")
	token, expiresIn, err := refreshAccessToken(RefreshToken)
	if err != nil {
		return err
	}
	TokenMutex.Lock()
	AccessToken = token
	TokenExpiry = time.Now().Add(time.Duration(expiresIn) * time.Second)
	TokenMutex.Unlock()
	logrus.Infof("Initial access token acquired, expires in %d seconds", expiresIn)
	return nil
}

// refreshTokenLoop periodically refreshes the access token before expiry
func refreshTokenLoop() {
	for {
		TokenMutex.Lock()
		sleepDuration := time.Until(TokenExpiry) - 10*time.Second
		TokenMutex.Unlock()

		if sleepDuration < 0 {
			sleepDuration = 10 * time.Second
		}

		time.Sleep(sleepDuration)

		token, expiresIn, err := refreshAccessToken(RefreshToken)
		if err != nil {
			logrus.WithError(err).Error("Token refresh failed, will retry")
			continue
		}

		TokenMutex.Lock()
		AccessToken = token
		TokenExpiry = time.Now().Add(time.Duration(expiresIn) * time.Second)
		TokenMutex.Unlock()
		logrus.Infof("Access token refreshed, expires in %d seconds", expiresIn)
	}
}

// refreshAccessToken calls the IdP token endpoint to refresh the access token
func refreshAccessToken(refreshToken string) (string, int, error) {
	logrus.Info("Sending token refresh request")

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", ClientId)
	data.Set("client_secret", ClientSecret)

	req, err := http.NewRequest("POST", TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("failed to call token endpoint: %w", err)
	}
	defer resp.Body.Close()

	// Read response body for logging and decoding
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, fmt.Errorf("failed to read token endpoint response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		logrus.WithFields(logrus.Fields{
			"status": resp.StatusCode,
			"body":   string(respBody),
		}).Debug("Token endpoint response")
		return "", 0, fmt.Errorf("refresh token request failed with status %s", resp.Status)
	}

	respData := struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}{}

	if err := json.Unmarshal(respBody, &respData); err != nil {
		return "", 0, fmt.Errorf("failed to parse token endpoint response: %w", err)
	}

	return respData.AccessToken, respData.ExpiresIn, nil
}
