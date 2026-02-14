package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

const refreshBuffer = 2 * time.Minute

type TokenEntry struct {
	Token   *oauth2.Token
	IDToken string
	mu      sync.Mutex
}

type TokenStore struct {
	mu     sync.RWMutex
	tokens map[string]*TokenEntry
}

var (
	store        = &TokenStore{tokens: make(map[string]*TokenEntry)}
	oauthConfig  *oauth2.Config
	authzServer  string
	startupError error
	HttpClient   = &http.Client{
		Transport: &localRedirectTransport{
			rt: http.DefaultTransport,
		},
		Timeout: 5 * time.Second,
	}
	ctx = context.WithValue(context.Background(), oauth2.HTTPClient, HttpClient)
	log = logrus.New()
)

func main() {
	setupLogger()

	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	authzServer = os.Getenv("AUTHZ_SERVER")

	if clientID == "" || clientSecret == "" || authzServer == "" {
		log.Fatal("CLIENT_ID, CLIENT_SECRET and AUTHZ_SERVER must be set")
	}

	log.WithFields(logrus.Fields{
		"authz_server": authzServer,
	}).Info("Starting token service")

	provider, err := oidc.NewProvider(ctx, authzServer)
	if err != nil {
		startupError = err
		log.WithError(err).Error("OIDC discovery failed")
	} else {
		oauthConfig = &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{"openid", "offline_access"},
		}
		log.Info("OIDC discovery successful")
	}

	http.HandleFunc("/token/", tokenHandler)
	http.HandleFunc("/loginstatus/", authorizedHandler)
	http.HandleFunc("/healthz", healthHandler)

	// Listen for SIGTERM
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	go func() {
		time.Sleep(10 * time.Second)
		<-ctx.Done()
		log.Println("SIGTERM/SIGINT received, starting shutdown procedure")
		waitForIngressUMA()
	}()

	log.Info("Listening on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.WithError(err).Fatal("Server exited")
	}
}

func setupLogger() {
	log.SetFormatter(&logrus.JSONFormatter{})
	log.SetOutput(os.Stdout)

	levelStr := strings.ToLower(os.Getenv("LOG_LEVEL"))
	if levelStr == "" {
		levelStr = "info"
	}

	level, err := logrus.ParseLevel(levelStr)
	if err != nil {
		log.Warnf("Invalid LOG_LEVEL '%s', defaulting to info", levelStr)
		level = logrus.InfoLevel
	}

	log.SetLevel(level)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if startupError != nil {
		log.WithError(startupError).Warn("Health check failed: discovery error")
		http.Error(w, "OIDC discovery failed", http.StatusServiceUnavailable)
		return
	}

	if oauthConfig == nil {
		log.Warn("Health check failed: OAuth config nil")
		http.Error(w, "OAuth config not initialized", http.StatusServiceUnavailable)
		return
	}

	req, _ := http.NewRequest(http.MethodHead, authzServer, nil)
	resp, err := HttpClient.Do(req)
	if err != nil || resp.StatusCode >= 500 {
		log.WithError(err).Warn("Auth server unreachable during health check")
		http.Error(w, "Auth server unreachable", http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func tokenHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Path[len("/token/"):]
	switch r.Method {
	case http.MethodPost:
		handleStore(w, r, userID)
	case http.MethodPut:
		handleUpdate(w, r, userID)
	case http.MethodGet:
		handleGet(w, r, userID)
	case http.MethodDelete:
		handleDelete(w, r, userID)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

type StoreRequest struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Expiry       int64  `json:"expiry"`
}

func handleStore(w http.ResponseWriter, r *http.Request, userID string) {
	_, exists := store.tokens[userID]
	if exists {
		log.WithField("user_id", userID).Warn("Token store requested but existing token found")
		http.Error(w, "User tokens already exists. Use PUT to update a token", 409)
		return
	}

	var req StoreRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.WithError(err).Warn("Invalid store request")
		http.Error(w, err.Error(), 400)
		return
	}

	token := &oauth2.Token{
		AccessToken:  req.AccessToken,
		RefreshToken: req.RefreshToken,
		TokenType:    "Bearer",
		Expiry:       time.Unix(req.Expiry, 0),
	}

	storeToken(userID, token, req.IDToken)

	w.WriteHeader(http.StatusCreated)
}

func handleUpdate(w http.ResponseWriter, r *http.Request, userID string) {
	_, exists := store.tokens[userID]
	if !exists {
		log.WithField("user_id", userID).Warn("Token update requested but no existing token found")
		http.Error(w, "User tokens not found. Use POST to create a token", 404)
		return
	}

	var req StoreRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.WithError(err).Warn("Invalid update request")
		http.Error(w, err.Error(), 400)
		return
	}

	token := &oauth2.Token{
		AccessToken:  req.AccessToken,
		RefreshToken: req.RefreshToken,
		TokenType:    "Bearer",
		Expiry:       time.Unix(req.Expiry, 0),
	}

	storeToken(userID, token, req.IDToken)

	w.WriteHeader(http.StatusOK)
}

func storeToken(userID string, token *oauth2.Token, idToken string) {
	store.mu.Lock()
	store.tokens[userID] = &TokenEntry{
		Token:   token,
		IDToken: idToken,
	}
	store.mu.Unlock()

	log.WithField("user_id", userID).Info("Stored token")
}

func handleGet(w http.ResponseWriter, _ *http.Request, userID string) {
	entry, err := getEntry(userID)
	if err != nil {
		log.WithField("user_id", userID).Warn("Token not found")
		http.Error(w, err.Error(), 404)
		return
	}

	token, idToken, err := ensureValidToken(entry, userID)
	if err != nil {
		log.WithError(err).WithField("user_id", userID).Error("Token refresh failed")
		http.Error(w, err.Error(), 500)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"access_token": token.AccessToken,
		"id_token":     idToken,
	})
}

func handleDelete(w http.ResponseWriter, _ *http.Request, userID string) {
	store.mu.Lock()
	delete(store.tokens, userID)
	store.mu.Unlock()

	log.WithField("user_id", userID).Info("Deleted token")
	w.WriteHeader(http.StatusNoContent)
}

func authorizedHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	userID := r.URL.Path[len("/loginstatus/"):]

	entry, err := getEntry(userID)
	if err != nil {
		log.WithField("user_id", userID).
			Warn("Authorization check failed: token not found")

		json.NewEncoder(w).Encode(map[string]bool{
			"login_status": false,
		})
		return
	}

	_, _, err = ensureValidToken(entry, userID)
	if err != nil {
		log.WithError(err).
			WithField("user_id", userID).
			Warn("Authorization check failed: refresh failed")

		json.NewEncoder(w).Encode(map[string]bool{
			"authorized": false,
		})
		return
	}

	log.WithField("user_id", userID).
		Debug("Authorization check successful")

	json.NewEncoder(w).Encode(map[string]bool{
		"authorized": true,
	})
}

func getEntry(userID string) (*TokenEntry, error) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	entry, ok := store.tokens[userID]
	if !ok {
		return nil, errors.New("not found")
	}
	return entry, nil
}

// ensureValidToken refreshes both access token and id token using refresh token
func ensureValidToken(entry *TokenEntry, userID string) (*oauth2.Token, string, error) {
	entry.mu.Lock()
	defer entry.mu.Unlock()

	now := time.Now()
	if entry.Token.Expiry.After(now.Add(refreshBuffer)) {
		return entry.Token, entry.IDToken, nil
	}

	log.WithField("user_id", userID).Info("Refreshing token using refresh token")

	ts := oauthConfig.TokenSource(ctx, entry.Token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, "", err
	}

	entry.Token = newToken

	// update ID token if returned
	if idv := newToken.Extra("id_token"); idv != nil {
		if idStr, ok := idv.(string); ok && idStr != "" {
			entry.IDToken = idStr
		}
	}

	return newToken, entry.IDToken, nil
}

// localRedirectTransport rewrites requests to localhost -> host.docker.internal
type localRedirectTransport struct {
	rt http.RoundTripper
}

func (t *localRedirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.HasPrefix(req.URL.Host, "localhost") || strings.HasPrefix(req.URL.Host, "127.0.0.1") {
		host, port, _ := net.SplitHostPort(req.URL.Host)
		if host == "" {
			host = req.URL.Host
		}
		if port != "" {
			req.URL.Host = fmt.Sprintf("host.docker.internal:%s", port)
		} else {
			req.URL.Host = "host.docker.internal"
		}
	}

	if req.Host == "" || req.Host == "localhost" || req.Host == "127.0.0.1" {
		req.Host = strings.Split(req.URL.Host, ":")[0]
	}

	return t.rt.RoundTrip(req)
}
