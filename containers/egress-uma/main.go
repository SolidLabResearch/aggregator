package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

var (
	ClientId      string
	ClientSecret  string
	AccessToken   string
	RefreshToken  string
	TokenMutex    sync.Mutex
	TokenExpiry   time.Time
	TokenEndpoint string
)

func main() {
	// Initialize logging
	logLevel, err := logrus.ParseLevel(os.Getenv("LOG_LEVEL"))
	if err != nil {
		logLevel = logrus.InfoLevel
	}
	logrus.SetLevel(logLevel)
	logrus.SetOutput(os.Stdout)

	// Read environment variables
	ClientId = os.Getenv("CLIENT_ID")
	ClientSecret = os.Getenv("CLIENT_SECRET")
	RefreshToken = os.Getenv("REFRESH_TOKEN")
	TokenEndpoint = os.Getenv("TOKEN_ENDPOINT")

	if ClientId == "" || ClientSecret == "" || RefreshToken == "" || TokenEndpoint == "" {
		logrus.Fatal("One or more required environment variables are missing")
	}

	// Refresh token before starting the server
	if err := initAccessToken(); err != nil {
		logrus.WithError(err).Fatal("Failed to initialize access token")
	}

	// Start a background goroutine to refresh the token automatically
	go refreshTokenLoop()

	// Start HTTP server
	http.HandleFunc("/", handleHTTPRequest)
	http.HandleFunc("/fetch", handleFetchRequest)
	logrus.Infof("UMA Proxy starting on port %d...", 8080)
	if err := http.ListenAndServe(":8080", nil); err != nil {
		logrus.Fatalf("Server failed: %v", err)
	}
}

func handleHTTPRequest(w http.ResponseWriter, r *http.Request) {
	// Do UMA flow
	resp, err := RequestWithUMA(&http.Client{Timeout: 10 * time.Second}, r)
	if err != nil {
		http.Error(w, "UMA request failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers and body
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
	logrus.WithFields(logrus.Fields{"url": resp.Request.URL, "status": resp.Status}).Info("UMA request completed")
}

func handleFetchRequest(w http.ResponseWriter, r *http.Request) {
	logrus.Info("Received /fetch request")

	if r.Method != http.MethodPost {
		http.Error(w, "Only POST is allowed for /fetch", http.StatusMethodNotAllowed)
		return
	}

	// Parse JSON payload
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var payload struct {
		TargetURL    string `json:"target_url"`
		TargetMethod string `json:"target_method"`
		TargetBody   string `json:"target_body"`
	}

	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		http.Error(w, "Invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if payload.TargetURL == "" {
		http.Error(w, "target_url is required", http.StatusBadRequest)
		return
	}

	if payload.TargetMethod == "" {
		payload.TargetMethod = http.MethodGet
	}

	// Build outbound request
	var outboundBody io.Reader = nil
	if payload.TargetBody != "" {
		outboundBody = bytes.NewReader([]byte(payload.TargetBody))
	}

	outReq, err := http.NewRequest(
		payload.TargetMethod,
		payload.TargetURL,
		outboundBody,
	)
	if err != nil {
		http.Error(w, "Failed to build target request: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Forward client headers except Host, Content-Length, etc.
	copySafeHeaders(outReq.Header, r.Header)

	logrus.WithFields(logrus.Fields{
		"target_url":    payload.TargetURL,
		"target_method": payload.TargetMethod,
	}).Info("Executing UMA-protected fetch request")

	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := RequestWithUMA(client, outReq)
	if err != nil {
		http.Error(w, "UMA fetch failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response back
	for key, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)

	logrus.WithFields(logrus.Fields{
		"status": resp.StatusCode,
	}).Info("/fetch completed")
}
