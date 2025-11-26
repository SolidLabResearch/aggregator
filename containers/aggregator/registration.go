package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type User struct {
	UserId       string `json:"user_id"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ASURL        string `json:"as_url"`
	Namespace    string `json:"namespace"`
}

func (u *User) ConfigEndpoints() map[string]string {
	return map[string]string{
		"actors": fmt.Sprintf("http://%s/config/%s/actors", ExternalHost, u.Namespace),
	}
}

var (
	users   = make(map[string]*User)
	userMux sync.Mutex
)

func initUserRegistration(mux *http.ServeMux) {
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		userRegistrationHandler(w, r, mux)
	})
}

func userRegistrationHandler(w http.ResponseWriter, r *http.Request, mux *http.ServeMux) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get external access token
	extAccessToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if extAccessToken == "" {
		logrus.Error("Missing Authorization header while registering user")
		http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
		return
	}

	// Get user id from token
	tokenInfo, err := extractUserInfo(extAccessToken)
	if err != nil {
		logrus.WithError(err).Error("Failed to extract user info from token")
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Verify the external access token
	_, err = verifyAccessToken(extAccessToken, tokenInfo.Issuer)
	if err != nil {
		logrus.WithError(err).Error("Failed to verify access token")
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Perform token exchange to get access and refresh tokens for aggregator client
	accessToken, refreshToken, err := exchangeToken(extAccessToken)
	if err != nil {
		logrus.WithError(err).Error("Token exchange failed")
		http.Error(w, "Token exchange failed", http.StatusInternalServerError)
		return
	}

	// Parse JSON body for as_url
	var body struct {
		ASURL string `json:"as_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		logrus.WithError(err).Error("Failed to parse request body")
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	if body.ASURL == "" {
		http.Error(w, "Missing as_url in body", http.StatusBadRequest)
		return
	}

	user := User{
		UserId:       tokenInfo.UserID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ASURL:        body.ASURL,
	}

	// Lock for safe concurrent access
	userMux.Lock()
	defer userMux.Unlock()

	// Check if user already exists
	if _, exists := users[user.UserId]; exists {
		http.Error(w, "User already registered", http.StatusConflict)
		return
	}

	// Create a unique namespace for the user
	ns, err := createNamespace(user)
	if err != nil {
		logrus.WithError(err).Errorf("Failed to create namespace for %s", user.UserId)
		http.Error(w, "Unable to create namespace", http.StatusInternalServerError)
		return
	}
	user.Namespace = ns

	// TODO: also set up egress uma

	// Initiate config endpoint
	initUserConfiguration(mux, user)

	// Store user
	users[user.UserId] = &user

	// Respond with the user config endpoint
	response := user.ConfigEndpoints()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

type TokenInfo struct {
	UserID string
	Issuer string
}

func extractUserInfo(token string) (*TokenInfo, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	// Decode payload (second part of JWT)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	// Parse JSON claims
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	// Extract sub and iss
	sub, ok := claims["sub"].(string)
	if !ok {
		return nil, fmt.Errorf("sub claim not found")
	}

	iss, ok := claims["iss"].(string)
	if !ok {
		return nil, fmt.Errorf("iss claim not found")
	}

	return &TokenInfo{
		UserID: sub,
		Issuer: iss,
	}, nil
}

// verifyAccessToken verifies the JWT using the issuer's JWKS endpoint.
// Returns the parsed token if valid.
func verifyAccessToken(tokenString string, issuer string) (jwt.Token, error) {
	// Build JWKS URL from issuer
	jwksURL := fmt.Sprintf("%s/protocol/openid-connect/certs", issuer)

	// Fetch JWKS from IdP
	keySet, err := jwk.Fetch(context.Background(), jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	// Parse and verify token using the key set
	token, err := jwt.Parse([]byte(tokenString), jwt.WithKeySet(keySet))
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	// Optional: Validate claims like issuer and expiration
	if token.Issuer() != issuer {
		return nil, fmt.Errorf("issuer mismatch: expected %s, got %s", issuer, token.Issuer())
	}

	return token, nil
}

func exchangeToken(extAccessToken string) (string, string, error) {
	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	data.Set("subject_token", extAccessToken)
	data.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	data.Set("requested_token_type", "urn:ietf:params:oauth:token-type:refresh_token")
	data.Set("client_id", ClientId)
	data.Set("client_secret", ClientSecret)

	tokenEndpoint, err := getTokenEndpoint(Idp)
	if err != nil {
		return "", "", err
	}

	resp, err := http.PostForm(tokenEndpoint, data)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", "", err
	}
	logrus.WithField("response", result).Debug("Token exchange response")

	accessToken, ok := result["access_token"].(string)
	if !ok {
		return "", "", fmt.Errorf("access_token not found")
	}
	refreshToken, _ := result["refresh_token"].(string)

	return accessToken, refreshToken, nil
}

func getTokenEndpoint(issuer string) (string, error) {
	url := fmt.Sprintf("%s/.well-known/openid-configuration", issuer)

	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to fetch OIDC config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("OIDC config error: %s", string(body))
	}

	var config struct {
		TokenEndpoint string `json:"token_endpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return "", fmt.Errorf("failed to parse OIDC config: %w", err)
	}

	if config.TokenEndpoint == "" {
		return "", fmt.Errorf("token_endpoint not found in OIDC config")
	}

	return config.TokenEndpoint, nil
}

func createNamespace(user User) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	nsName := uuid.NewString()
	// Create namespace with labels/annotations
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: nsName,
			Labels: map[string]string{
				"created-by": "aggregator",
			},
			Annotations: map[string]string{
				"owner":  user.UserId,
				"as_url": user.ASURL,
			},
		},
	}

	_, err := Clientset.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to create namespace %s: %w", nsName, err)
	}

	logrus.Infof("Namespace %s created successfully ✅", nsName)

	return nsName, nil
}
