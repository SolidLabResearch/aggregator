package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"

	"ingress-uma/auth"
	"ingress-uma/signing"

	"github.com/sirupsen/logrus"
)

var ExternalHost = os.Getenv("EXTERNAL_HOST")

func init() {
	// Set up logging
	LogLevel, err := logrus.ParseLevel(strings.ToLower(os.Getenv("LOG_LEVEL")))
	if err != nil {
		LogLevel = logrus.InfoLevel
	}
	logrus.SetLevel(LogLevel)
	logrus.SetOutput(os.Stdout)
}

func main() {
	mux := http.NewServeMux()
	signing.InitSigning(mux, "/keys/private_key.pem", ExternalHost)
	auth.InitAuth(ExternalHost)

	mux.HandleFunc("/authorize", auth.AuthorizeRequest)
	mux.HandleFunc("/resources", resourcesHandler)

	// Wrap the mux with the logging middleware
	loggedMux := loggingMiddleware(mux)

	logrus.Info("Starting UMA RS auth server on :8080")
	if err := http.ListenAndServe(":8080", loggedMux); err != nil {
		logrus.Fatalf("Server failed: %v", err)
	}
}

func resourcesHandler(w http.ResponseWriter, r *http.Request) {
	// Only accept POST requests
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var reqData struct {
		Issuer     string   `json:"issuer"`
		ResourceID string   `json:"resource_id"`
		Scopes     []string `json:"scopes"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqData); err != nil {
		logrus.WithError(err).Warn("Invalid JSON in request body")
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Basic validation
	if reqData.Issuer == "" || reqData.ResourceID == "" || len(reqData.Scopes) == 0 {
		http.Error(w, "Missing required fields: issuer, resource_id, scopes", http.StatusBadRequest)
		return
	}

	// Convert string scopes to []Scope
	scopes := make([]auth.Scope, len(reqData.Scopes))
	for i, s := range reqData.Scopes {
		scopes[i] = auth.Scope(s)
	}

	logrus.WithFields(logrus.Fields{
		"issuer":      reqData.Issuer,
		"resource_id": reqData.ResourceID,
		"scopes":      reqData.Scopes,
	}).Info("Received resource registration request")

	if err := auth.CreateResource(reqData.Issuer, reqData.ResourceID, scopes); err != nil {
		logrus.WithError(err).Error("Failed to create UMA resource")
		http.Error(w, "Failed to register resource", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
}

// loggingMiddleware wraps a handler and logs every request
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(strings.NewReader(string(bodyBytes))) // reset body for next handler

		logrus.WithFields(logrus.Fields{
			"method":  r.Method,
			"path":    r.URL.Path,
			"headers": r.Header,
			"body":    string(bodyBytes),
		}).Info("Incoming request")

		next.ServeHTTP(w, r)
	})
}
