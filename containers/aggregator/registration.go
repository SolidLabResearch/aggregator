package main

import (
	"crypto/rand"
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

var stateStore = make(map[string]RegistrationRequest) // state to as_url mapping

type RegistrationRequest struct {
	AuthzServerURL  string `json:"as_url"`
	UserIdp         string `json:"openid_provider"`
	SuccessRedirect string `json:"success_redirect"`
	FailRedirect    string `json:"fail_redirect"`
}

type User struct {
	UserId         string
	AccessToken    string
	RefreshToken   string
	AuthzServerURL string
	Namespace      string
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

	mux.HandleFunc("/registration", registrationHandler)
	mux.HandleFunc("/registration/callback", func(w http.ResponseWriter, r *http.Request) {
		registrationCallback(w, r, mux)
	})
}

// registrationHandler now accepts POST (form or JSON) and returns a redirect to the IdP auth endpoint
func registrationHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegistrationRequest

	// Accept either form values or JSON body for convenience
	contentType := r.Header.Get("Content-Type")
	if contentType == "application/json" || strings.HasPrefix(contentType, "application/json;") {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
	} else {
		// Parse form
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form body", http.StatusBadRequest)
			return
		}
		req.UserIdp = r.FormValue("openid_provider")
		req.AuthzServerURL = r.FormValue("as_url")
		req.SuccessRedirect = r.FormValue("success_redirect")
		req.FailRedirect = r.FormValue("fail_redirect")
	}

	if req.UserIdp == "" || req.AuthzServerURL == "" || req.SuccessRedirect == "" || req.FailRedirect == "" {
		http.Error(w, "missing required fields", http.StatusBadRequest)
		return
	}

	// Discover auth endpoint
	authURL, err := getAuthEndpoint(req.UserIdp)
	if err != nil {
		logrus.WithError(err).Error("Failed to get authn endpoint")
		http.Error(w, "Failed to get authn endpoint", http.StatusInternalServerError)
		return
	}

	state, err := generateRandomState()
	if err != nil {
		logrus.WithError(err).Error("Failed to generate state")
		http.Error(w, "Failed to generate state", http.StatusInternalServerError)
		return
	}

	// Store the registration request for callback (state -> req mapping)
	stateStore[state] = req

	// Build auth URL with parameters
	params := url.Values{
		"redirect_uri":  {fmt.Sprintf("%s://%s/registration/callback", Protocol, ExternalHost)},
		"state":         {state},
		"scope":         {"openid profile email"},
		"response_type": {"code"},
		"client_id":     {ClientId},
	}
	redirectTo := fmt.Sprintf("%s?%s", authURL, params.Encode())

	// Redirect browser to IdP authorization endpoint
	http.Redirect(w, r, redirectTo, http.StatusFound)
}

func registrationCallback(w http.ResponseWriter, r *http.Request, mux *http.ServeMux) {
	// Extract code and state from query parameters
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		http.Error(w, "Missing code or state", http.StatusBadRequest)
		return
	}

	// Validate state
	req, ok := stateStore[state]
	if !ok {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}
	delete(stateStore, state) // Prevent replay attacks

	// Get access token using the code
	tokenEndpoint, err := getTokenEndpoint(req.UserIdp)
	if err != nil {
		logrus.WithError(err).Error("Failed to get token endpoint")
		http.Redirect(w, r, req.FailRedirect, http.StatusFound)
		return
	}

	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {fmt.Sprintf("%s://%s/registration/callback", Protocol, ExternalHost)},
		"client_id":     {ClientId},
		"client_secret": {ClientSecret},
	}

	resp, err := http.PostForm(tokenEndpoint, data)
	if err != nil {
		logrus.WithError(err).Error("Token exchange failed")
		http.Redirect(w, r, req.FailRedirect, http.StatusFound)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logrus.Errorf("Token endpoint returned %d", resp.StatusCode)
		http.Redirect(w, r, req.FailRedirect, http.StatusFound)
		return
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		logrus.WithError(err).Error("Failed to parse token response")
		http.Redirect(w, r, req.FailRedirect, http.StatusFound)
		return
	}

	// Verify and validate the ID token
	idToken, err := verifyToken(tokenResp.IDToken, req.UserIdp)
	if err != nil {
		logrus.WithError(err).Error("Failed to verify ID token")
		http.Redirect(w, r, req.FailRedirect, http.StatusFound)
		return
	}
	userId, err := validateToken(idToken, req.UserIdp)
	if err != nil {
		logrus.WithError(err).Error("Failed to validate ID token")
		http.Redirect(w, r, req.FailRedirect, http.StatusFound)
		return
	}

	// complete registration process by creating a user
	user := User{
		UserId:         userId,
		AccessToken:    tokenResp.AccessToken,
		RefreshToken:   tokenResp.RefreshToken,
		AuthzServerURL: req.AuthzServerURL,
	}

	// Lock for safe concurrent access
	userMux.Lock()
	defer userMux.Unlock()

	// Check if user already exists
	if _, exists := users[user.UserId]; exists {
		http.Redirect(w, r, req.FailRedirect, http.StatusFound)
		return
	}

	// Create a unique namespace for the user
	ns, err := createNamespace(user)
	if err != nil {
		logrus.WithError(err).Errorf("Failed to create namespace for %s", user.UserId)
		http.Redirect(w, r, req.FailRedirect, http.StatusFound)
		return
	}
	user.Namespace = ns

	// Initiate config endpoint
	initUserConfiguration(mux, user)

	// Store user
	users[user.UserId] = &user

	// Prepare endpoints payload to send back to the UI
	endpoints := user.ConfigEndpoints()
	endpointsJSON, _ := json.Marshal(endpoints)
	payload := base64.StdEncoding.EncodeToString(endpointsJSON)

	// Build redirect URL: success_redirect?flow=success&payload=<url-escaped-base64>
	successURL, err := url.Parse(req.SuccessRedirect)
	if err != nil {
		logrus.WithError(err).Error("invalid success redirect")
		http.Redirect(w, r, req.FailRedirect, http.StatusFound)
		return
	}
	q := successURL.Query()
	q.Set("payload", url.QueryEscape(payload))
	successURL.RawQuery = q.Encode()

	http.Redirect(w, r, successURL.String(), http.StatusFound)
}

func generateRandomState() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// verifyToken verifies the JWT using the issuer's JWKS endpoint.
// Returns the parsed token if valid.
func verifyToken(tokenString string, issuer string) (jwt.Token, error) {
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

	return token, nil
}

// validateToken checks standard claims of the token. and returns the user id if valid.
func validateToken(token jwt.Token, idp string) (string, error) {
	// Check expiration
	exp := token.Expiration()
	if time.Now().After(exp) {
		return "", fmt.Errorf("token has expired")
	}

	// Check issuer
	iss, ok := token.Get("iss")
	if !ok || iss.(string) != idp {
		return "", fmt.Errorf("invalid issuer")
	}
	// Extract user id (sub claim)
	sub, ok := token.Get("sub")
	if !ok {
		return "", fmt.Errorf("sub claim not found")
	}

	userID, ok := sub.(string)
	if !ok {
		return "", fmt.Errorf("invalid sub claim type")
	}

	return userID, nil
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

func getAuthEndpoint(issuer string) (string, error) {
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
		AuthnEndpoint string `json:"authorization_endpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return "", fmt.Errorf("failed to parse OIDC config: %w", err)
	}

	if config.AuthnEndpoint == "" {
		return "", fmt.Errorf("authorization_endpoint not found in OIDC config")
	}

	return config.AuthnEndpoint, nil
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
				"as_url": user.AuthzServerURL,
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
