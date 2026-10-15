package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

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
		TargetBodyB64 string                 `json:"bodyBase64"`
		AuthMode      string                 `json:"authMode"`
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

	authMode := strings.ToLower(strings.TrimSpace(payload.AuthMode))
	if authMode == "" {
		authMode = "auto"
	}
	if authMode != "auto" && authMode != "oauth" {
		http.Error(w, "authMode must be either auto or oauth", http.StatusBadRequest)
		return
	}

	logrus.WithFields(logrus.Fields{
		"target_url":    payload.TargetURL,
		"target_method": payload.TargetMethod,
		"auth_mode":     authMode,
	}).Info("Preparing outbound request")

	if payload.TargetBody != "" && payload.TargetBodyB64 != "" {
		http.Error(w, "body and bodyBase64 are mutually exclusive", http.StatusBadRequest)
		return
	}
	var outboundBody io.Reader
	if payload.TargetBodyB64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(payload.TargetBodyB64)
		if err != nil {
			http.Error(w, "bodyBase64 must be valid base64", http.StatusBadRequest)
			return
		}
		outboundBody = bytes.NewReader(decoded)
		logrus.WithField("target_body_size", len(decoded)).Debug("Prepared base64-decoded outbound body")
	} else if payload.TargetBody != "" {
		outboundBody = bytes.NewReader([]byte(payload.TargetBody))
		logrus.WithField("target_body_size", len(payload.TargetBody)).Debug("Prepared outbound body")
	}

	// Tie the upstream request to the caller's connection: when the caller
	// disconnects (for example a cancelled event stream), the pod request and
	// any UMA token exchange are cancelled too.
	outReq, err := http.NewRequestWithContext(r.Context(), payload.TargetMethod, payload.TargetURL, outboundBody)
	if err != nil {
		logrus.WithError(err).Error("Failed to build outbound request")
		http.Error(w, "Failed to build target request: "+err.Error(), http.StatusBadRequest)
		return
	}

	outReq.Header = model.NormalizeHeaders(payload.TargetHeaders)

	// Log outbound request headers
	model.LogHeaders("Outbound request headers", outReq.Header)

	var resp *http.Response
	if authMode == "oauth" {
		resp, err = RequestWithOAuth(model.HttpClient, outReq)
	} else {
		resp, err = RequestWithUMA(model.HttpClient, outReq)
	}
	if err != nil {
		logrus.WithError(err).WithField("auth_mode", authMode).Error("Authenticated fetch failed")
		http.Error(w, "Authenticated fetch failed: "+err.Error(), http.StatusBadGateway)
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
	isEventStream := strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream")
	if isEventStream {
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
	// Send the headers now. Otherwise they only leave with the first body
	// bytes, and a quiet event stream leaves the caller waiting for headers.
	flusher.Flush()

	copyResponseBody(w, flusher, resp.Body, r, isEventStream, SSEKeepAliveInterval)
}

// SSEKeepAliveInterval is how often an idle event stream gets a comment line,
// so idle timeouts on the way to the caller do not close it.
var SSEKeepAliveInterval = 30 * time.Second

// copyResponseBody streams the upstream body to the caller, flushing every
// chunk. For event streams it also writes a ": keepalive" comment when the
// stream has been idle for keepAlive. Comments are only written between
// events, so they never split an event that arrives in several chunks.
func copyResponseBody(w io.Writer, flusher http.Flusher, body io.Reader, r *http.Request, isEventStream bool, keepAlive time.Duration) {
	var mu sync.Mutex
	atBoundary := true // nothing written yet, or the last write ended an event
	lastWrite := time.Now()

	if isEventStream && keepAlive > 0 {
		done := make(chan struct{})
		defer close(done)
		go func() {
			ticker := time.NewTicker(keepAlive / 2)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					return
				case <-ticker.C:
					mu.Lock()
					if atBoundary && time.Since(lastWrite) >= keepAlive {
						if _, err := io.WriteString(w, ": keepalive\n\n"); err == nil {
							flusher.Flush()
						}
						lastWrite = time.Now()
					}
					mu.Unlock()
				}
			}
		}()
	}

	buf := make([]byte, 1024)
	for {
		n, err := body.Read(buf)
		if n > 0 {
			mu.Lock()
			_, writeErr := w.Write(buf[:n])
			if writeErr == nil {
				flusher.Flush()
				atBoundary = bytes.HasSuffix(buf[:n], []byte("\n\n")) || bytes.HasSuffix(buf[:n], []byte("\r\n\r\n"))
				lastWrite = time.Now()
			}
			mu.Unlock()
			if writeErr != nil {
				logrus.WithError(writeErr).Error("Failed writing to downstream")
				return
			}
		}
		if err != nil {
			if r.Context().Err() != nil {
				logrus.Info("Downstream closed the connection; upstream request cancelled")
			} else if err != io.EOF {
				logrus.WithError(err).Error("Error reading upstream")
			}
			return
		}
	}
}
