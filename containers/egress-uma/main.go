package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"

	"egress-uma/model"

	"github.com/sirupsen/logrus"
)

var (
	AggregatorID string
	OIDCServer   string
)

func main() {
	logLevel, err := logrus.ParseLevel(os.Getenv("LOG_LEVEL"))
	if err != nil {
		logLevel = logrus.InfoLevel
	}
	logrus.SetLevel(logLevel)
	logrus.SetOutput(os.Stdout)

	AggregatorID = os.Getenv("AGGREGATOR_ID")
	if AggregatorID == "" {
		logrus.Fatal("AGGREGATOR_ID is not set")
	}
	OIDCServer = os.Getenv("OIDC_SERVER")

	_, err = getAccessToken()
	if err != nil {
		logrus.WithError(err).Error("Failed to obtain initial access token")
	} else {
		logrus.Info("Successfully obtained initial access token")
	}

	http.HandleFunc("/", handleHTTPRequest)
	http.HandleFunc("/fetch", handleFetchRequest)

	logrus.Infof("UMA Proxy starting on port %d...", 8080)
	if err := http.ListenAndServe(":8080", nil); err != nil {
		logrus.Fatalf("Server failed: %v", err)
	}
}

func handleHTTPRequest(w http.ResponseWriter, r *http.Request) {
	resp, err := RequestWithUMA(model.HttpClient, r)
	if err != nil {
		http.Error(w, "UMA request failed: "+err.Error(), http.StatusBadGateway)
		return
	}

	io.Copy(w, resp.Body)
}

func handleFetchRequest(w http.ResponseWriter, r *http.Request) {
	logrus.WithFields(logrus.Fields{
		"method": r.Method,
		"url":    r.URL.String(),
	}).Info("Received /fetch request")

	// Log incoming request headers
	model.LogHeaders("Incoming request headers", r.Header)

	if r.Method != http.MethodPost {
		logrus.Warn("Invalid method for /fetch")
		http.Error(w, "Only POST is allowed for /fetch", http.StatusMethodNotAllowed)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		logrus.WithError(err).Error("Failed to read request body")
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	logrus.WithField("body_size", len(bodyBytes)).Debug("Read incoming request body")

	var payload struct {
		TargetURL     string                 `json:"url"`
		TargetMethod  string                 `json:"method"`
		TargetHeaders map[string]interface{} `json:"headers"`
		TargetBody    string                 `json:"body"`
	}

	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		logrus.WithError(err).Error("Invalid JSON body")
		http.Error(w, "Invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if payload.TargetURL == "" {
		logrus.Warn("Missing target_url in payload")
		http.Error(w, "target_url is required", http.StatusBadRequest)
		return
	}

	if payload.TargetMethod == "" {
		payload.TargetMethod = http.MethodGet
	}

	logrus.WithFields(logrus.Fields{
		"target_url":    payload.TargetURL,
		"target_method": payload.TargetMethod,
	}).Info("Preparing outbound request")

	var outboundBody io.Reader
	if payload.TargetBody != "" {
		outboundBody = bytes.NewReader([]byte(payload.TargetBody))
		logrus.WithField("target_body_size", len(payload.TargetBody)).Debug("Prepared outbound body")
	}

	outReq, err := http.NewRequest(payload.TargetMethod, payload.TargetURL, outboundBody)
	if err != nil {
		logrus.WithError(err).Error("Failed to build outbound request")
		http.Error(w, "Failed to build target request: "+err.Error(), http.StatusBadRequest)
		return
	}

	outReq.Header = model.NormalizeHeaders(payload.TargetHeaders)

	// Log outbound request headers
	model.LogHeaders("Outbound request headers", outReq.Header)

	// Send request using UMA proxy
	resp, err := RequestWithUMA(model.HttpClient, outReq)
	if err != nil {
		logrus.WithError(err).Error("UMA fetch failed")
		http.Error(w, "UMA fetch failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	logrus.WithField("status", resp.StatusCode).Info("Received response from upstream")

	// Log upstream response headers
	model.LogHeaders("Upstream response headers", resp.Header)

	// --- Forward upstream headers to downstream
	for k, v := range resp.Header {
		for _, vv := range v {
			w.Header().Add(k, vv)
		}
	}

	// Ensure SSE headers are present if upstream sent text/event-stream
	if resp.Header.Get("Content-Type") == "text/event-stream" {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
	}

	w.WriteHeader(resp.StatusCode)

	logrus.Debug("Starting to stream response body to downstream")

	flusher, ok := w.(http.Flusher)
	if !ok {
		logrus.Error("ResponseWriter does not implement Flusher")
		return
	}

	buf := make([]byte, 1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, writeErr := w.Write(buf[:n]); writeErr != nil {
				logrus.WithError(writeErr).Error("Failed writing to downstream")
				return
			}
			flusher.Flush()
		}
		if err != nil {
			if err != io.EOF {
				logrus.WithError(err).Error("Error reading upstream")
			}
			break
		}
	}
}
