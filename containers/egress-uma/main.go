package main

import (
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
