package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

const refreshBuffer = 2 * time.Minute

type TokenEntry struct {
	Token       *oauth2.Token
	IDToken     string
	OAuthConfig *oauth2.Config
	Issuer      string
	mu          sync.Mutex
}

type TokenStore struct {
	mu     sync.RWMutex
	tokens map[string]*TokenEntry
}

var (
	store      = &TokenStore{tokens: make(map[string]*TokenEntry)}
	HttpClient = &http.Client{
		Transport: &localRedirectTransport{
			rt: http.DefaultTransport,
		},
		Timeout: 0,
	}
	ctx = context.WithValue(context.Background(), oauth2.HTTPClient, HttpClient)
	log = logrus.New()
)

func main() {
	setupLogger()

	log.Info("Starting token service")

	http.HandleFunc("/token", tokenHandler)
	http.HandleFunc("/loginstatus", authorizedHandler)
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
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func tokenHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		handleStore(w, r)
	case http.MethodPut:
		handleUpdate(w, r)
	case http.MethodGet:
		handleGet(w, r)
	case http.MethodDelete:
		handleDelete(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

type StoreRequest struct {
	UserID       string `json:"user_id"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Expiry       int64  `json:"expiry"`
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

func handleStore(w http.ResponseWriter, r *http.Request) {
	var req StoreRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.WithError(err).Warn("Invalid store request")
		http.Error(w, err.Error(), 400)
		return
	}

	_, exists := store.tokens[req.UserID]
	if exists {
		log.WithField("user_id", req.UserID).Warn("Token store requested but existing token found")
		http.Error(w, "User tokens already exists. Use PUT to update a token", 409)
		return
	}

	provider, err := oidc.NewProvider(ctx, req.Issuer)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	oauthConfig := &oauth2.Config{
		ClientID: req.ClientID,
		Endpoint: provider.Endpoint(),
		Scopes:   []string{"openid", "offline_access"},
	}

	if req.ClientSecret != "" {
		oauthConfig.ClientSecret = req.ClientSecret
	}

	token := &oauth2.Token{
		AccessToken:  req.AccessToken,
		RefreshToken: req.RefreshToken,
		TokenType:    "Bearer",
		Expiry:       time.Unix(req.Expiry, 0),
	}

	storeToken(req.UserID, token, req.IDToken, oauthConfig, req.Issuer)

	w.WriteHeader(http.StatusCreated)
}

func handleUpdate(w http.ResponseWriter, r *http.Request) {
	var req StoreRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.WithError(err).Warn("Invalid update request")
		http.Error(w, err.Error(), 400)
		return
	}

	_, exists := store.tokens[req.UserID]
	if !exists {
		log.WithField("user_id", req.UserID).Warn("Token update requested but no existing token found")
		http.Error(w, "User tokens not found. Use POST to create a token", 404)
		return
	}

	provider, err := oidc.NewProvider(ctx, req.Issuer)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	oauthConfig := &oauth2.Config{
		ClientID: req.ClientID,
		Endpoint: provider.Endpoint(),
		Scopes:   []string{"openid", "offline_access"},
	}

	if req.ClientSecret != "" {
		oauthConfig.ClientSecret = req.ClientSecret
	}

	token := &oauth2.Token{
		AccessToken:  req.AccessToken,
		RefreshToken: req.RefreshToken,
		TokenType:    "Bearer",
		Expiry:       time.Unix(req.Expiry, 0),
	}

	storeToken(req.UserID, token, req.IDToken, oauthConfig, req.Issuer)

	w.WriteHeader(http.StatusOK)
}

func storeToken(userID string, token *oauth2.Token, idToken string, config *oauth2.Config, url string) {
	store.mu.Lock()
	store.tokens[userID] = &TokenEntry{
		Token:       token,
		IDToken:     idToken,
		OAuthConfig: config,
		Issuer:      url,
	}
	store.mu.Unlock()

	log.WithField("user_id", userID).Info("Stored token")
}

func handleGet(w http.ResponseWriter, r *http.Request) {
	// Get the userID from the query parameter
	encodedID := r.URL.Query().Get("id")
	if encodedID == "" {
		http.Error(w, "Missing 'id' query parameter", http.StatusBadRequest)
		return
	}

	// URL-decode the userID
	userID, err := url.QueryUnescape(encodedID)
	if err != nil {
		http.Error(w, "Invalid 'id' query parameter", http.StatusBadRequest)
		return
	}

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

func handleDelete(w http.ResponseWriter, r *http.Request) {
	// Get the userID from the query parameter
	encodedID := r.URL.Query().Get("id")
	if encodedID == "" {
		http.Error(w, "Missing 'id' query parameter", http.StatusBadRequest)
		return
	}

	// URL-decode the userID
	userID, err := url.QueryUnescape(encodedID)
	if err != nil {
		http.Error(w, "Invalid 'id' query parameter", http.StatusBadRequest)
		return
	}

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

	// Get the userID from the query parameter
	encodedID := r.URL.Query().Get("id")
	if encodedID == "" {
		http.Error(w, "Missing 'id' query parameter", http.StatusBadRequest)
		return
	}

	// URL-decode the userID
	userID, err := url.QueryUnescape(encodedID)
	if err != nil {
		http.Error(w, "Invalid 'id' query parameter", http.StatusBadRequest)
		return
	}

	entry, err := getEntry(userID)
	if err != nil {
		log.WithField("user_id", userID).
			Warn("Authorization check failed: token not found")

		json.NewEncoder(w).Encode(map[string]bool{
			"login_status": false,
		})
		return
	}

	token, _, err := ensureValidToken(entry, userID)
	if err != nil {
		log.WithError(err).
			WithField("user_id", userID).
			Warn("Authorization check failed: refresh failed")

		json.NewEncoder(w).Encode(map[string]bool{
			"login_status": false,
		})
		return
	}

	log.WithField("user_id", userID).
		Debug("Authorization check successful")

	json.NewEncoder(w).Encode(map[string]interface{}{
		"login_status": true,
		"token_expiry": token.Expiry.Format(time.RFC3339),
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

	if entry.OAuthConfig.ClientSecret == "" {
		// TODO: allow public client refresh (e.g. Solid-OIDC / DPoP support)
		return nil, "", errors.New("token expired and refresh not supported for public clients")
	}

	ts := entry.OAuthConfig.TokenSource(ctx, entry.Token)
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
