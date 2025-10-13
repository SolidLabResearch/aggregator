package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/maartyman/rdfgo"
	"github.com/sirupsen/logrus"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// SolidAuth manages client credentials and access tokens for Solid OIDC
type SolidAuth struct {
	webId        string
	cssBaseURL   string
	dpopKey      *ecdsa.PrivateKey
	authString   string
	accessToken  string
	expiresAt    time.Time
	mu           sync.RWMutex
	refreshTimer *time.Timer
}

// NewSolidAuth creates a new SolidAuth instance
func NewSolidAuth(webId string) *SolidAuth {
	return &SolidAuth{
		webId: webId,
	}
}

// Init initializes the client credentials
func (sa *SolidAuth) Init(email, password string) error {
	// Redirect localhost WebID URLs to host machine for Kubernetes
	req, err := createRequestWithRedirect("GET", sa.webId, nil)
	if err != nil {
		return fmt.Errorf("failed to create WebID request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch WebID profile: %w", err)
	}
	defer resp.Body.Close()

	stream, errChan := rdfgo.Parse(resp.Body, rdfgo.ParserOptions{Format: "text/turtle", BaseIRI: sa.webId})

	for quad := range stream {
		if quad.GetPredicate().GetValue() == "http://www.w3.org/ns/solid/terms#oidcIssuer" {
			sa.cssBaseURL = quad.GetObject().GetValue()
			break
		}
	}
	if err := <-errChan; err != nil {
		return fmt.Errorf("failed to parse WebID profile: %w", err)
	}
	if sa.cssBaseURL == "" {
		return fmt.Errorf("OIDC issuer not found in WebID profile")
	}

	// Generate DPoP key pair
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate DPoP key: %w", err)
	}
	sa.dpopKey = key

	// Step 1: Get controls from account endpoint
	reqAccount, err := createRequestWithRedirect("GET", sa.cssBaseURL+".account/", nil)
	if err != nil {
		return fmt.Errorf("failed to create account request: %w", err)
	}

	indexResp, err := http.DefaultClient.Do(reqAccount)
	if err != nil {
		return fmt.Errorf("failed to get account controls: %w", err)
	}
	defer indexResp.Body.Close()

	var indexData struct {
		Controls struct {
			Password struct {
				Login string `json:"login"`
			} `json:"password"`
		} `json:"controls"`
	}
	if err := json.NewDecoder(indexResp.Body).Decode(&indexData); err != nil {
		return fmt.Errorf("failed to decode account controls: %w", err)
	}

	// Step 2: Login with password
	loginData := map[string]string{
		"email":    email,
		"password": password,
	}
	loginBody, _ := json.Marshal(loginData)

	reqLogin, err := createRequestWithRedirect("POST", indexData.Controls.Password.Login, bytes.NewReader(loginBody))
	if err != nil {
		return fmt.Errorf("failed to create login request: %w", err)
	}
	reqLogin.Header.Set("Content-Type", "application/json")

	loginResp, err := http.DefaultClient.Do(reqLogin)
	if err != nil {
		return fmt.Errorf("failed to login: %w", err)
	}
	defer loginResp.Body.Close()

	if loginResp.StatusCode != http.StatusOK {
		return fmt.Errorf("login failed with status: %d", loginResp.StatusCode)
	}

	var loginResult struct {
		Authorization string `json:"authorization"`
	}
	if err := json.NewDecoder(loginResp.Body).Decode(&loginResult); err != nil {
		return fmt.Errorf("failed to decode login response: %w", err)
	}

	// Step 3: Get controls with authorization
	req3, err := createRequestWithRedirect("GET", sa.cssBaseURL+".account/", nil)
	if err != nil {
		return fmt.Errorf("failed to create authenticated controls request: %w", err)
	}
	req3.Header.Set("Authorization", "CSS-Account-Token "+loginResult.Authorization)

	indexResp2, err := http.DefaultClient.Do(req3)
	if err != nil {
		return fmt.Errorf("failed to get authenticated controls: %w", err)
	}
	defer indexResp2.Body.Close()

	if indexResp2.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to get authenticated controls with status: %d", indexResp2.StatusCode)
	}

	var indexData2 struct {
		Controls struct {
			Account struct {
				ClientCredentials string `json:"clientCredentials"`
			} `json:"account"`
		} `json:"controls"`
	}
	if err := json.NewDecoder(indexResp2.Body).Decode(&indexData2); err != nil {
		return fmt.Errorf("failed to decode authenticated controls: %w", err)
	}

	// Step 4: Create client credentials
	credData := map[string]string{
		"name":  "uma-proxy-token",
		"webId": sa.webId,
	}
	credBody, _ := json.Marshal(credData)

	req2, err := createRequestWithRedirect("POST", indexData2.Controls.Account.ClientCredentials, bytes.NewReader(credBody))
	if err != nil {
		return fmt.Errorf("failed to create credentials request: %w", err)
	}
	req2.Header.Set("Authorization", "CSS-Account-Token "+loginResult.Authorization)
	req2.Header.Set("Content-Type", "application/json")

	credResp, err := http.DefaultClient.Do(req2)
	if err != nil {
		return fmt.Errorf("failed to create client credentials: %w", err)
	}
	defer credResp.Body.Close()

	var credResult struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(credResp.Body).Decode(&credResult); err != nil {
		return fmt.Errorf("failed to decode client credentials: %w", err)
	}

	sa.authString = url.QueryEscape(credResult.ID) + ":" + url.QueryEscape(credResult.Secret)

	logrus.WithFields(logrus.Fields{"webid": sa.webId}).Info("✅ Client credentials initialized for WebID")

	// Get initial access token
	return sa.refreshAccessToken()
}

// refreshAccessToken gets a new access token
func (sa *SolidAuth) refreshAccessToken() error {
	sa.mu.Lock()
	defer sa.mu.Unlock()

	if sa.authString == "" || sa.dpopKey == nil {
		return fmt.Errorf("not initialized")
	}

	tokenURL := sa.cssBaseURL + ".oidc/token"

	// Create DPoP header with the ORIGINAL URL (not redirected), because the server sees the original Host header
	dpopHeader, err := sa.createDPoPHeader(tokenURL, "POST")
	if err != nil {
		return fmt.Errorf("failed to create DPoP header: %w", err)
	}

	req, err := createRequestWithRedirect("POST", tokenURL, bytes.NewReader([]byte("grant_type=client_credentials&scope=webid")))
	if err != nil {
		return fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(sa.authString)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", dpopHeader)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to get access token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyText, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("token request failed with status: %d, and body: %s", resp.StatusCode, bodyText)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("failed to decode token response: %w", err)
	}

	sa.accessToken = tokenResp.AccessToken
	sa.expiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	logrus.WithFields(logrus.Fields{"expires_at": sa.expiresAt.Format(time.RFC3339)}).Info("✅ Access token refreshed")

	// Schedule next refresh 500ms before expiry
	refreshIn := time.Duration(tokenResp.ExpiresIn)*time.Second - 500*time.Millisecond
	if refreshIn < 0 {
		refreshIn = 0
	}

	if sa.refreshTimer != nil {
		sa.refreshTimer.Stop()
	}
	sa.refreshTimer = time.AfterFunc(refreshIn, func() {
		if err := sa.refreshAccessToken(); err != nil {
			logrus.WithFields(logrus.Fields{"err": err}).Error("❌ Failed to auto-refresh access token")
		}
	})

	return nil
}

// GetAccessToken returns the current access token (thread-safe)
func (sa *SolidAuth) GetAccessToken() string {
	sa.mu.RLock()
	defer sa.mu.RUnlock()
	return sa.accessToken
}

// CreateClaimToken creates a claim token with DPoP for UMA flow
func (sa *SolidAuth) CreateClaimToken(tokenEndpoint string) (string, error) {
	sa.mu.RLock()
	accessToken := sa.accessToken
	sa.mu.RUnlock()

	if accessToken == "" || sa.dpopKey == nil {
		return "", fmt.Errorf("not initialized")
	}

	dpopHeader, err := sa.createDPoPHeader(tokenEndpoint, "POST")
	if err != nil {
		return "", fmt.Errorf("failed to create DPoP header: %w", err)
	}

	claimToken := map[string]string{
		"Authorization": "DPoP " + accessToken,
		"DPoP":          dpopHeader,
	}

	claimTokenJSON, err := json.Marshal(claimToken)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claim token: %w", err)
	}

	return string(claimTokenJSON), nil
}

// createDPoPHeader creates a DPoP header JWT
func (sa *SolidAuth) createDPoPHeader(htu, htm string) (string, error) {
	// Create JWK from public key
	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(sa.dpopKey.PublicKey.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(sa.dpopKey.PublicKey.Y.Bytes()),
	}

	// Create header
	header := map[string]interface{}{
		"alg": "ES256",
		"typ": "dpop+jwt",
		"jwk": jwk,
	}

	// Create payload
	payload := map[string]interface{}{
		"htu": htu,
		"htm": htm,
		"jti": generateJTI(),
		"iat": time.Now().Unix(),
	}

	// Encode header and payload
	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Sign
	message := headerB64 + "." + payloadB64
	hash := sha256.Sum256([]byte(message))

	r, s, err := ecdsa.Sign(rand.Reader, sa.dpopKey, hash[:])
	if err != nil {
		return "", err
	}

	// Encode signature
	signature := append(r.Bytes(), s.Bytes()...)
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	return message + "." + signatureB64, nil
}

// generateJTI generates a random JTI for DPoP
func generateJTI() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
