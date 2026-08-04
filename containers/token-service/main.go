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
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
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
	log       = logrus.New()
	Clientset *kubernetes.Clientset
	Namespace string
)

func main() {
	setupLogger()

	log.Info("Loading in-cluster Kubernetes configuration")
	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		log.WithError(err).Fatal("Failed to load in-cluster config")
	}

	Clientset, err = kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		log.WithError(err).Fatal("Failed to create Kubernetes client")
	}
	log.Info("Kubernetes client initialized")

	Namespace = os.Getenv("NAMESPACE")
	if Namespace == "" {
		log.Fatal("Environment variable NAMESPACE must be set")
	}
	log.WithField("namespace", Namespace).Info("Namespace loaded")

	log.Info("Starting token service")

	http.HandleFunc("/token", tokenHandler)
	http.HandleFunc("/loginstatus", authorizedHandler)
	http.HandleFunc("/healthz", healthHandler)

	signalContext, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	server := &http.Server{Addr: ":8080", Handler: nil}
	go func() {
		log.Info("Listening on :8080")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.WithError(err).Error("HTTP server exited")
			stop()
		}
	}()

	<-signalContext.Done()
	log.Info("SIGTERM/SIGINT received, starting shutdown procedure")

	// Keep serving tokens briefly while ingress-uma removes its registrations,
	// but never consume the entire Kubernetes termination grace period.
	waitContext, cancelWait := context.WithTimeout(context.Background(), 45*time.Second)
	if err := waitForIngressUMA(waitContext); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		log.WithError(err).Warn("Failed while waiting for ingress-uma shutdown")
	}
	cancelWait()

	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()
	if err := server.Shutdown(shutdownContext); err != nil {
		log.WithError(err).Warn("HTTP server did not shut down cleanly")
	}
	log.Info("Token service stopped")
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
	log.WithField("level", level.String()).Info("Logger initialized")
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func tokenHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	log.WithFields(logrus.Fields{
		"method": r.Method,
		"path":   r.URL.Path,
	}).Debug("Token handler invoked")

	switch r.Method {
	case http.MethodPut:
		handleUpsert(ctx, w, r)
	case http.MethodGet:
		handleGet(ctx, w, r)
	case http.MethodDelete:
		handleDelete(w, r)
	default:
		log.WithField("method", r.Method).Warn("Token handler received unsupported method")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

type StoreRequest struct {
	AggregatorID string `json:"aggregator_id"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Expiry       int64  `json:"expiry"`
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
}

func handleUpsert(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	var req StoreRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.WithError(err).Warn("Failed to decode upsert request body")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.AggregatorID == "" {
		log.Warn("Upsert request missing aggregator_id")
		http.Error(w, "aggregator_id is required", http.StatusBadRequest)
		return
	}

	l := log.WithFields(logrus.Fields{
		"aggregator_id": req.AggregatorID,
		"issuer":        req.Issuer,
	})

	store.mu.RLock()
	_, exists := store.tokens[req.AggregatorID]
	store.mu.RUnlock()

	l.WithField("exists", exists).Debug("Resolved existing token state for upsert")

	// Inject custom HTTP client so oidc.NewProvider uses localRedirectTransport
	ctx = oidc.ClientContext(ctx, HttpClient)

	// Initialize OIDC provider
	provider, err := oidc.NewProvider(ctx, req.Issuer)
	if err != nil {
		l.WithError(err).Error("Failed to initialize OIDC provider")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	clientID := strings.TrimSpace(req.ClientID)
	clientSecret := req.ClientSecret
	credentialSource := "request"
	if clientID == "" {
		// Backward compatibility for tokens created before callers supplied
		// credentials directly. Dynamic-registration code may also reuse this.
		clientID, clientSecret, err = getClientCredentials(req.AggregatorID)
		if err != nil {
			l.WithError(err).Error("Failed to resolve client credentials")
			http.Error(w, "Failed to get client credentials", http.StatusInternalServerError)
			return
		}
		credentialSource = "kubernetes-secret"
	}
	l.WithFields(logrus.Fields{
		"client_id":         clientID,
		"credential_source": credentialSource,
	}).Debug("Resolved client credentials")

	oauthConfig := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{"openid", "offline_access"},
	}

	token := &oauth2.Token{
		AccessToken:  req.AccessToken,
		RefreshToken: req.RefreshToken,
		TokenType:    "Bearer",
		Expiry:       time.Unix(req.Expiry, 0),
	}

	storeToken(req.AggregatorID, token, req.IDToken, oauthConfig, req.Issuer)

	if exists {
		l.WithField("token_expiry", token.Expiry.UTC().Format(time.RFC3339)).Info("Token updated")
		w.WriteHeader(http.StatusOK)
	} else {
		l.WithField("token_expiry", token.Expiry.UTC().Format(time.RFC3339)).Info("Token created")
		w.WriteHeader(http.StatusCreated)
	}
}

func storeToken(aggregatorID string, token *oauth2.Token, idToken string, config *oauth2.Config, issuer string) {
	store.mu.Lock()
	store.tokens[aggregatorID] = &TokenEntry{
		Token:       token,
		IDToken:     idToken,
		OAuthConfig: config,
		Issuer:      issuer,
	}
	store.mu.Unlock()
}

func handleGet(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	encodedID := r.URL.Query().Get("id")
	if encodedID == "" {
		log.Warn("GET /token request missing 'id' query parameter")
		http.Error(w, "Missing 'id' query parameter", http.StatusBadRequest)
		return
	}

	aggregatorID, err := url.QueryUnescape(encodedID)
	if err != nil {
		log.WithField("raw_id", encodedID).Warn("Failed to URL-decode aggregator ID")
		http.Error(w, "Invalid 'id' query parameter", http.StatusBadRequest)
		return
	}

	l := log.WithField("aggregator_id", aggregatorID)

	entry, err := getEntry(aggregatorID)
	if err != nil {
		l.Warn("Token lookup failed: entry not found")
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	token, idToken, err := ensureValidToken(ctx, entry, aggregatorID)
	if err != nil {
		l.WithError(err).Error("Failed to obtain valid token")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	l.WithField("token_expiry", token.Expiry.UTC().Format(time.RFC3339)).
		Debug("Returning valid token")

	json.NewEncoder(w).Encode(map[string]string{
		"access_token": token.AccessToken,
		"id_token":     idToken,
	})
}

func handleDelete(w http.ResponseWriter, r *http.Request) {
	encodedID := r.URL.Query().Get("id")
	if encodedID == "" {
		log.Warn("DELETE /token request missing 'id' query parameter")
		http.Error(w, "Missing 'id' query parameter", http.StatusBadRequest)
		return
	}

	aggregatorID, err := url.QueryUnescape(encodedID)
	if err != nil {
		log.WithField("raw_id", encodedID).Warn("Failed to URL-decode aggregator ID")
		http.Error(w, "Invalid 'id' query parameter", http.StatusBadRequest)
		return
	}

	store.mu.Lock()
	_, exists := store.tokens[aggregatorID]
	delete(store.tokens, aggregatorID)
	store.mu.Unlock()

	if exists {
		log.WithField("aggregator_id", aggregatorID).Info("Token deleted")
	} else {
		log.WithField("aggregator_id", aggregatorID).Warn("Delete requested for non-existent token")
	}
	w.WriteHeader(http.StatusNoContent)
}

func authorizedHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if r.Method != http.MethodGet {
		log.WithField("method", r.Method).Warn("authorizedHandler received unsupported method")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	encodedID := r.URL.Query().Get("id")
	if encodedID == "" {
		log.Warn("GET /loginstatus request missing 'id' query parameter")
		http.Error(w, "Missing 'id' query parameter", http.StatusBadRequest)
		return
	}

	userID, err := url.QueryUnescape(encodedID)
	if err != nil {
		log.WithField("raw_id", encodedID).Warn("Failed to URL-decode user ID")
		http.Error(w, "Invalid 'id' query parameter", http.StatusBadRequest)
		return
	}

	l := log.WithField("user_id", userID)

	entry, err := getEntry(userID)
	if err != nil {
		l.Warn("Login status check: token not found")
		json.NewEncoder(w).Encode(map[string]bool{"login_status": false})
		return
	}

	token, _, err := ensureValidToken(ctx, entry, userID)
	if err != nil {
		l.WithError(err).Warn("Login status check: token refresh failed")
		json.NewEncoder(w).Encode(map[string]bool{"login_status": false})
		return
	}

	l.WithField("token_expiry", token.Expiry.UTC().Format(time.RFC3339)).
		Debug("Login status check: authorized")

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
func ensureValidToken(ctx context.Context, entry *TokenEntry, aggregatorID string) (*oauth2.Token, string, error) {
	entry.mu.Lock()
	defer entry.mu.Unlock()

	l := log.WithField("aggregator_id", aggregatorID)

	now := time.Now()
	if entry.Token.Expiry.After(now.Add(refreshBuffer)) {
		l.WithField("token_expiry", entry.Token.Expiry.UTC().Format(time.RFC3339)).
			Debug("Token still valid; no refresh needed")
		return entry.Token, entry.IDToken, nil
	}

	l.WithFields(logrus.Fields{
		"token_expiry":   entry.Token.Expiry.UTC().Format(time.RFC3339),
		"refresh_buffer": refreshBuffer.String(),
	}).Info("Token within refresh buffer; refreshing")

	if entry.OAuthConfig.ClientSecret == "" {
		l.Warn("Token refresh skipped: public client has no client secret")
		return nil, "", errors.New("token expired and refresh not supported for public clients")
	}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, HttpClient)
	ts := entry.OAuthConfig.TokenSource(ctx, entry.Token)
	newToken, err := ts.Token()
	if err != nil {
		l.WithError(err).Error("Token refresh failed")
		return nil, "", err
	}

	entry.Token = newToken

	idToken := entry.IDToken
	if idv := newToken.Extra("id_token"); idv != nil {
		if idStr, ok := idv.(string); ok && idStr != "" {
			entry.IDToken = idStr
			idToken = idStr
			l.Debug("ID token updated from refresh response")
		}
	}

	l.WithField("new_token_expiry", newToken.Expiry.UTC().Format(time.RFC3339)).
		Info("Token refreshed successfully")

	return newToken, idToken, nil
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
