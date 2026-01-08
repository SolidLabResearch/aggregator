package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// createClaimToken returns a valid access token, refreshing if necessary
func createClaimToken() (string, error) {
	if ok, err := syncTokensFromFile(); err != nil {
		logrus.WithError(err).Warn("Failed to load tokens from file")
	} else if ok {
		TokenMutex.Lock()
		token := AccessToken
		TokenMutex.Unlock()
		return token, nil
	}

	TokenMutex.Lock()
	if AccessToken != "" && time.Until(TokenExpiry) > 30*time.Second {
		token := AccessToken
		TokenMutex.Unlock()
		return token, nil
	}
	TokenMutex.Unlock()

	refreshToken, err := getRefreshToken()
	if err != nil {
		markTokenInvalid(err)
		return "", err
	}

	// Request a new access token using the refresh token
	newToken, expiresIn, newRefresh, err := refreshAccessToken(refreshToken)
	if err != nil {
		markTokenInvalid(err)
		return "", err
	}

	TokenMutex.Lock()
	AccessToken = newToken
	TokenExpiry = time.Now().Add(time.Duration(expiresIn) * time.Second)
	if newRefresh != "" {
		RefreshToken = newRefresh
	}
	TokenMutex.Unlock()

	if newRefresh == "" {
		newRefresh = refreshToken
	}
	updateTokenStatus(time.Now().Add(time.Duration(expiresIn)*time.Second).UTC(), newRefresh, newToken)
	return newToken, nil
}

// initAccessToken initializes the access token once at startup
func initAccessToken() error {
	logrus.Info("Acquiring inital access token...")
	if ok, err := syncTokensFromFile(); err != nil {
		logrus.WithError(err).Warn("Failed to load tokens from file")
	} else if ok {
		TokenMutex.Lock()
		expiry := TokenExpiry
		refreshToken := RefreshToken
		accessToken := AccessToken
		TokenMutex.Unlock()
		updateTokenStatus(expiry, refreshToken, accessToken)
		return nil
	}

	refreshToken, err := getRefreshToken()
	if err != nil {
		markTokenInvalid(err)
		return err
	}
	token, expiresIn, newRefresh, err := refreshAccessToken(refreshToken)
	if err != nil {
		markTokenInvalid(err)
		return err
	}
	TokenMutex.Lock()
	AccessToken = token
	TokenExpiry = time.Now().Add(time.Duration(expiresIn) * time.Second)
	if newRefresh != "" {
		RefreshToken = newRefresh
	}
	TokenMutex.Unlock()
	logrus.Infof("Initial access token acquired, expires in %d seconds", expiresIn)
	if newRefresh == "" {
		newRefresh = refreshToken
	}
	updateTokenStatus(time.Now().Add(time.Duration(expiresIn)*time.Second).UTC(), newRefresh, token)
	return nil
}

// refreshTokenLoop periodically refreshes the access token before expiry
func refreshTokenLoop() {
	for {
		if _, err := syncTokensFromFile(); err != nil {
			logrus.WithError(err).Warn("Failed to load tokens from file")
		}

		TokenMutex.Lock()
		sleepDuration := time.Until(TokenExpiry) - 10*time.Second
		TokenMutex.Unlock()

		if sleepDuration < 0 {
			sleepDuration = 10 * time.Second
		}

		time.Sleep(sleepDuration)

		refreshToken, err := getRefreshToken()
		if err != nil {
			logrus.WithError(err).Error("No refresh token available, will retry")
			markTokenInvalid(err)
			continue
		}
		token, expiresIn, newRefresh, err := refreshAccessToken(refreshToken)
		if err != nil {
			logrus.WithError(err).Error("Token refresh failed, will retry")
			markTokenInvalid(err)
			continue
		}

		TokenMutex.Lock()
		AccessToken = token
		TokenExpiry = time.Now().Add(time.Duration(expiresIn) * time.Second)
		if newRefresh != "" {
			RefreshToken = newRefresh
		}
		TokenMutex.Unlock()
		logrus.Infof("Access token refreshed, expires in %d seconds", expiresIn)
		if newRefresh == "" {
			newRefresh = refreshToken
		}
		updateTokenStatus(time.Now().Add(time.Duration(expiresIn)*time.Second).UTC(), newRefresh, token)
	}
}

// refreshAccessToken calls the IdP token endpoint to refresh the access token
func refreshAccessToken(refreshToken string) (string, int, string, error) {
	logrus.Info("Sending token refresh request")

	if strings.TrimSpace(TokenEndpoint) == "" {
		return "", 0, "", errors.New("token endpoint not configured")
	}

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", ClientId)
	data.Set("client_secret", ClientSecret)

	req, err := http.NewRequest("POST", TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return "", 0, "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, "", fmt.Errorf("failed to call token endpoint: %w", err)
	}
	defer resp.Body.Close()

	// Read response body for logging and decoding
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, "", fmt.Errorf("failed to read token endpoint response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		logrus.WithFields(logrus.Fields{
			"status": resp.StatusCode,
			"body":   string(respBody),
		}).Debug("Token endpoint response")
		return "", 0, "", fmt.Errorf("refresh token request failed with status %s", resp.Status)
	}

	respData := struct {
		AccessToken  string `json:"access_token"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
	}{}

	if err := json.Unmarshal(respBody, &respData); err != nil {
		return "", 0, "", fmt.Errorf("failed to parse token endpoint response: %w", err)
	}

	return respData.AccessToken, respData.ExpiresIn, respData.RefreshToken, nil
}

func getRefreshToken() (string, error) {
	TokenMutex.Lock()
	cached := RefreshToken
	TokenMutex.Unlock()
	if cached != "" {
		return cached, nil
	}

	if _, err := syncTokensFromFile(); err == nil {
		TokenMutex.Lock()
		cached = RefreshToken
		TokenMutex.Unlock()
		if cached != "" {
			return cached, nil
		}
	}

	return "", errors.New("no refresh token available")
}

func syncTokensFromFile() (bool, error) {
	if UpdateTokensFile == "" {
		return false, nil
	}

	payload, err := readTokensFile(UpdateTokensFile)
	if err != nil {
		return false, err
	}

	var expiry time.Time
	if payload.AccessTokenExpiry != "" {
		parsed, err := time.Parse(time.RFC3339, payload.AccessTokenExpiry)
		if err != nil {
			return false, fmt.Errorf("invalid access_token_expiry: %w", err)
		}
		expiry = parsed
	}

	TokenMutex.Lock()
	if payload.AccessToken != "" {
		AccessToken = payload.AccessToken
	}
	if payload.RefreshToken != "" {
		RefreshToken = payload.RefreshToken
	}
	if payload.AccessToken != "" {
		if !expiry.IsZero() {
			TokenExpiry = expiry
		} else {
			TokenExpiry = time.Time{}
		}
	}
	token := AccessToken
	tokenExpiry := TokenExpiry
	TokenMutex.Unlock()

	if token != "" && !tokenExpiry.IsZero() && time.Until(tokenExpiry) > 30*time.Second {
		return true, nil
	}

	return false, nil
}

func readTokensFile(path string) (tokenFilePayload, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return tokenFilePayload{}, fmt.Errorf("failed to read tokens file: %w", err)
	}
	var payload tokenFilePayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return tokenFilePayload{}, fmt.Errorf("failed to parse tokens file: %w", err)
	}
	payload.AccessToken = strings.TrimSpace(payload.AccessToken)
	payload.RefreshToken = strings.TrimSpace(payload.RefreshToken)
	payload.AccessTokenExpiry = strings.TrimSpace(payload.AccessTokenExpiry)
	if payload.AccessToken == "" && payload.RefreshToken == "" {
		return tokenFilePayload{}, errors.New("tokens file is empty")
	}
	return payload, nil
}
