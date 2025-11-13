package main

import (
	"aggregator/auth"
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
	"io"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// AuthProxy handles UMA authorization for both regular and streaming requests
type AuthProxy struct {
	activeStreams map[string]*Stream
	baseURL       string
	endpointUrl   string
	mutex         sync.RWMutex
	upgrader      websocket.Upgrader
}

// Stream tracks the lifecycle of an authorized streaming session.
type Stream struct {
	SessionID   string
	ResourceURL string
	Scope       auth.ResourceScope
	Token       string
	ExpiresAt   time.Time
	timer       *time.Timer
	cancelFunc  context.CancelFunc
}

var AuthProxyInstance *AuthProxy

// NewAuthProxy creates a new auth proxy instancetype
func InitAuthProxy(mux *http.ServeMux, baseURL string) {
	AuthProxyInstance = &AuthProxy{
		activeStreams: make(map[string]*Stream),
		baseURL:       baseURL,
		endpointUrl:   baseURL + "/service/tokens",
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Configure as needed for security
			},
		},
	}
	mux.HandleFunc("/service/tokens", AuthProxyInstance.serviceTokenEndpoint)
	err := auth.CreateResource(
		AuthProxyInstance.endpointUrl,
		[]auth.ResourceScope{auth.ScopeCreate},
		nil,
	)
	if err != nil {
		panic(err)
	}
}

// setCORSProxy adds CORS headers for actor (proxied) responses & token service
func setCORSProxy(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Methods", "GET, POST, DELETE, HEAD, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept, Origin, Cache-Control, X-Requested-With, If-None-Match, Last-Event-ID")
	h.Set("Access-Control-Expose-Headers", "ETag, Link")
	h.Set("Access-Control-Max-Age", "600")
}

// HandleAllRequests is the main request handler that implements the UMA flow
func (ap *AuthProxy) HandleAllRequests(w http.ResponseWriter, r *http.Request) {
	setCORSProxy(w)
	if r.Method == http.MethodOptions { // Preflight for any actor resource
		w.WriteHeader(http.StatusNoContent)
		return
	}
	fullUrl := fmt.Sprintf("%s%s", ap.baseURL, r.URL.Path)
	logrus.WithFields(logrus.Fields{
		"method": r.Method,
		"url":    fullUrl,
	}).Debug("🔍 Processing request")

	streamResource, isStream := auth.IsStreamingResource(fullUrl)
	if isStream {
		ap.handleStreamRequest(w, r, streamResource)
		return
	}
	ap.handleRegularRequest(w, r)
}

// handleStreamRequest handles streaming requests with auth headers
func (ap *AuthProxy) handleStreamRequest(w http.ResponseWriter, r *http.Request, streamResource *auth.StreamingResource) {
	ap.addServiceTokenLinkHeader(w)

	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader == "" || !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		ap.requestStreamTicket(w, r)
		return
	}

	token := strings.TrimSpace(authHeader[7:])
	claims, err := auth.ParseStreamToken(token, ap.baseURL, streamResource.URL)
	if err != nil {
		logrus.WithError(err).Warn("Invalid stream token")
		ap.requestStreamTicket(w, r)
		return
	}

	ap.mutex.RLock()
	stream, exists := ap.activeStreams[claims.SessionID]
	ap.mutex.RUnlock()
	if !exists || stream == nil {
		logrus.WithField("session_id", claims.SessionID).Warn("Stream session not found")
		ap.requestStreamTicket(w, r)
		return
	}

	if stream.Token != token {
		logrus.WithFields(logrus.Fields{
			"session_id": claims.SessionID,
		}).Warn("Stream token mismatch for session")
		ap.requestStreamTicket(w, r)
		return
	}

	if stream.ResourceURL != streamResource.URL {
		logrus.WithFields(logrus.Fields{
			"session_id": stream.SessionID,
			"resource":   stream.ResourceURL,
		}).Warn("Stream resource mismatch")
		ap.requestStreamTicket(w, r)
		return
	}

	if stream.Scope != streamResource.Scope {
		logrus.WithFields(logrus.Fields{
			"session_id": stream.SessionID,
		}).Warn("Stream scope mismatch")
		ap.requestStreamTicket(w, r)
		return
	}

	if time.Now().After(stream.ExpiresAt) {
		logrus.WithFields(logrus.Fields{
			"session_id": stream.SessionID,
		}).Warn("Stream token expired")
		ap.requestStreamTicket(w, r)
		return
	}

	if err := ap.proxyStreamRequest(w, r, stream); err != nil {
		logrus.WithError(err).Error("Failed to proxy stream request")
		http.Error(w, "Failed to proxy stream request", http.StatusBadGateway)
	}
}

// handleRegularRequest handles non-streaming requests with auth headers
func (ap *AuthProxy) handleRegularRequest(w http.ResponseWriter, r *http.Request) {
	if !auth.AuthorizeRequest(w, r, nil) {
		return
	}

	actorID, relPath, err := extractActorAndPath(r.URL.Path)
	if err != nil {
		ap.writeStreamError(w, err)
		return
	}

	registration, _, err := resolveRegisteredResource(actorID, relPath)
	if err != nil {
		ap.writeStreamError(w, err)
		return
	}

	if err := ap.proxyToBackend(w, r, registration, relPath, false); err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"actor_id": actorID,
			"path":     relPath,
		}).Error("Failed to proxy request")
		http.Error(w, "Failed to proxy request", http.StatusBadGateway)
	}
}

// serviceTokenEndpoint handles the /service/tokens endpoint
func (ap *AuthProxy) serviceTokenEndpoint(w http.ResponseWriter, r *http.Request) {
	setCORSProxy(w)
	if r.Method == http.MethodOptions { // Preflight for tokens endpoint
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	logrus.Debug("🎫 Service token endpoint called")
	var request serviceTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	request.normalize()
	if request.ResourceURL == "" {
		http.Error(w, "resource_url is required", http.StatusBadRequest)
		return
	}
	streamResource, isStream := auth.IsStreamingResource(request.ResourceURL)
	var extraPermissions []auth.Permission
	if isStream {
		extraPermissions = []auth.Permission{{ResourceID: request.ResourceURL, ResourceScopes: []string{string(streamResource.Scope)}}}
	}
	logrus.WithFields(logrus.Fields{"ExtraPermissionsAmount": len(extraPermissions), "ResourceID": request.ResourceURL}).Debug("setting extraPermissions")
	if !auth.AuthorizeRequest(w, r, extraPermissions) {
		return
	}
	if !isStream {
		http.Error(w, "Resource is not a streaming resource", http.StatusBadRequest)
		return
	}
	if request.SessionID != "" {
		if err := ap.refreshStreamToken(w, r, request); err != nil {
			ap.writeStreamError(w, err)
		}
		return
	}
	if err := ap.createStreamToken(w, r, request, streamResource); err != nil {
		ap.writeStreamError(w, err)
		return
	}
}

type serviceTokenRequest struct {
	ResourceURL string               `json:"resource_url"`
	ResourceID  string               `json:"resource_id"`
	Scopes      []auth.ResourceScope `json:"resource_scopes"`
	SessionID   string               `json:"session_id"`
}

func (req *serviceTokenRequest) normalize() {
	if req.ResourceURL == "" {
		req.ResourceURL = req.ResourceID
	}
}

func (ap *AuthProxy) writeStreamError(w http.ResponseWriter, err error) {
	var statusErr *streamError
	if errors.As(err, &statusErr) {
		http.Error(w, statusErr.Message, statusErr.Status)
		return
	}
	http.Error(w, "Internal server error", http.StatusInternalServerError)
}

type streamError struct {
	Message string
	Status  int
}

func (e *streamError) Error() string {
	return e.Message
}

func (ap *AuthProxy) createStreamToken(w http.ResponseWriter, r *http.Request, request serviceTokenRequest, streamResource *auth.StreamingResource) error {
	request.SessionID = uuid.NewString()
	return ap.issueStreamToken(w, r, request, streamResource)
}

func (ap *AuthProxy) refreshStreamToken(w http.ResponseWriter, r *http.Request, request serviceTokenRequest) error {
	ap.mutex.RLock()
	stream, exists := ap.activeStreams[request.SessionID]
	ap.mutex.RUnlock()
	if !exists {
		return &streamError{Message: "Stream session not found", Status: http.StatusNotFound}
	}
	if stream.ResourceURL != request.ResourceURL && stream.ResourceURL != "" {
		return &streamError{Message: "Stream session resource mismatch", Status: http.StatusBadRequest}
	}

	umaExp, _, err := ap.determineStreamLifetime(r)
	if err != nil {
		return err
	}

	ap.mutex.Lock()
	stream.ExpiresAt = umaExp
	ap.scheduleStreamTimerLocked(stream)
	ap.mutex.Unlock()

	response := map[string]interface{}{
		"session_id":         stream.SessionID,
		"session_expires_at": umaExp.Unix(),
	}
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(response)
}

func (ap *AuthProxy) issueStreamToken(w http.ResponseWriter, r *http.Request, request serviceTokenRequest, streamResource *auth.StreamingResource) error {
	expiresAt, ttl, err := ap.determineStreamLifetime(r)
	if err != nil {
		return err
	}

	token, tokenExpiresAt, err := auth.GenerateStreamToken(request.SessionID, request.ResourceURL, ap.baseURL, streamResource.Scope, ttl)
	if err != nil {
		return err
	}

	ap.mutex.Lock()
	stream, exists := ap.activeStreams[request.SessionID]
	if !exists {
		stream = &Stream{
			SessionID:   request.SessionID,
			ResourceURL: request.ResourceURL,
			Scope:       streamResource.Scope,
		}
		ap.activeStreams[request.SessionID] = stream
	} else {
		stream.Scope = streamResource.Scope
	}
	stream.Token = token
	stream.ExpiresAt = expiresAt
	ap.scheduleStreamTimerLocked(stream)
	ap.mutex.Unlock()

	logrus.WithFields(logrus.Fields{
		"session_id":         stream.SessionID,
		"resource":           stream.ResourceURL,
		"session_expires_in": expiresAt.Sub(time.Now()).Seconds(),
	}).Info("Issued stream token")

	response := map[string]interface{}{
		"session_id":         stream.SessionID,
		"service_token":      stream.Token,
		"token_expires_at":   tokenExpiresAt.Unix(),
		"session_expires_at": expiresAt.Unix(),
	}
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(response)
}

func (ap *AuthProxy) determineStreamLifetime(r *http.Request) (time.Time, time.Duration, error) {
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader == "" {
		return time.Time{}, 0, &streamError{Message: "Missing UMA authorization header", Status: http.StatusUnauthorized}
	}

	token := strings.TrimSpace(authHeader)
	if strings.HasPrefix(strings.ToLower(token), "bearer ") {
		token = strings.TrimSpace(token[7:])
	}

	introspection, err := auth.Introspect(token)
	if err != nil {
		logrus.WithError(err).Error("Failed to introspect UMA token")
		return time.Time{}, 0, &streamError{Message: "Failed to introspect UMA token", Status: http.StatusBadGateway}
	}

	if !introspection.Active {
		return time.Time{}, 0, &streamError{Message: "UMA token inactive", Status: http.StatusUnauthorized}
	}

	if introspection.Exp <= 0 {
		return time.Time{}, 0, &streamError{Message: "UMA token missing expiration", Status: http.StatusUnauthorized}
	}
	exp := time.Unix(introspection.Exp, 0)
	ttl := time.Until(exp)
	if ttl <= 0 {
		return time.Time{}, 0, &streamError{Message: "UMA token expired", Status: http.StatusUnauthorized}
	}
	return exp, ttl, nil
}

func (ap *AuthProxy) requestStreamTicket(w http.ResponseWriter, r *http.Request) {
	extra := []auth.Permission{
		{
			ResourceID:     ap.endpointUrl,
			ResourceScopes: []string{string(auth.ScopeCreate)},
		},
	}
	originalAuth := r.Header.Get("Authorization")
	if originalAuth != "" {
		r.Header.Del("Authorization")
		defer r.Header.Set("Authorization", originalAuth)
	}
	if auth.AuthorizeRequest(w, r, extra) {
		http.Error(w, "Forbidden", http.StatusForbidden)
	}
}

func (ap *AuthProxy) scheduleStreamTimerLocked(stream *Stream) {
	if stream.timer != nil {
		stream.timer.Stop()
	}
	delay := time.Until(stream.ExpiresAt)
	if delay <= 0 {
		delay = time.Millisecond
	}
	stream.timer = time.AfterFunc(delay, func() {
		ap.stopStream(stream)
	})
}

func (ap *AuthProxy) stopStream(stream *Stream) {
	ap.mutex.Lock()
	defer ap.mutex.Unlock()
	_, exists := ap.activeStreams[stream.SessionID]
	if exists {
		delete(ap.activeStreams, stream.SessionID)
	}
	if stream.timer != nil {
		stream.timer.Stop()
		stream.timer = nil
	}
	if stream.cancelFunc != nil {
		stream.cancelFunc()
		stream.cancelFunc = nil
	}
	logrus.WithField("session_id", stream.SessionID).Info("Stream session expired")
}

func (ap *AuthProxy) proxyStreamRequest(w http.ResponseWriter, r *http.Request, stream *Stream) error {
	actorID, relPath, err := extractActorAndPath(r.URL.Path)
	if err != nil {
		return err
	}

	registration, _, err := resolveRegisteredResource(actorID, relPath)
	if err != nil {
		return err
	}

	logrus.WithFields(logrus.Fields{"actor_id": actorID, "path": relPath, "session_id": stream.SessionID}).Info("Proxying streaming request")
	return ap.pipeSSE(w, r, registration, relPath, actorID, stream)
}

// pipeSSE opens an upstream SSE connection to the pod and relays it to the client.
func (ap *AuthProxy) pipeSSE(w http.ResponseWriter, r *http.Request, registration *ResourceRegistration, relPath string, actorID string, stream *Stream) error {
	preferredHost := resolveServiceTarget(actorID)
	targetHost := preferredHost
	if targetHost == "" {
		targetHost = resolveTargetHost(registration.PodIP, registration.Port)
	}

	backendPath := normalizeRelativePath(relPath)
	targetURL := &url.URL{Scheme: "http", Host: targetHost, Path: backendPath}
	logrus.WithFields(logrus.Fields{"target": targetURL.Host, "url": targetURL.String()}).Info("Piping SSE to backend")

	cancelableContext, cancel := context.WithCancel(r.Context())
	ap.mutex.Lock()
	stream, exists := ap.activeStreams[stream.SessionID]
	if !exists {
		ap.mutex.Unlock()
		cancel()
		return &streamError{Message: "Stream session not found", Status: http.StatusNotFound}
	}
	stream.cancelFunc = cancel
	ap.mutex.Unlock()
	upReq, err := http.NewRequestWithContext(cancelableContext, http.MethodGet, targetURL.String(), nil)
	if err != nil {
		return err
	}
	upReq.Header.Set("Accept", "text/event-stream")
	upReq.Header.Set("Cache-Control", "no-cache")
	upReq.Header.Set("Connection", "keep-alive")
	if lastEventID := r.Header.Get("Last-Event-ID"); lastEventID != "" {
		upReq.Header.Set("Last-Event-ID", lastEventID)
	}
	// Forward a minimal set of headers except auth
	for k, vv := range r.Header {
		if strings.EqualFold(k, "Authorization") {
			continue
		}
		if strings.EqualFold(k, "Host") {
			continue
		}
		for _, v := range vv {
			upReq.Header.Add(k, v)
		}
	}
	upReq.Host = targetURL.Host

	upRes, err := (&http.Client{}).Do(upReq)
	if err != nil {
		if isContextCanceledError(err) {
			logrus.WithFields(logrus.Fields{"target": targetHost, "path": backendPath}).Error("Upstream SSE context canceled")
			http.Error(w, "Failed to connect upstream", http.StatusBadGateway)
			ap.stopStream(stream)
			return nil
		}
		logrus.WithError(err).WithFields(logrus.Fields{"target": targetHost, "path": backendPath}).Error("Upstream SSE request failed")
		http.Error(w, "Failed to connect upstream", http.StatusBadGateway)
		ap.stopStream(stream)
		return nil
	}
	logrus.WithFields(logrus.Fields{"status": upRes.Status, "target": targetHost, "path": backendPath}).Info("Upstream SSE connected")
	defer upRes.Body.Close()
	if upRes.StatusCode != http.StatusOK {
		logrus.WithFields(logrus.Fields{"status": upRes.Status, "target": targetHost, "path": backendPath}).Warn("Upstream SSE non-200")
		http.Error(w, "Upstream error", http.StatusBadGateway)
		ap.stopStream(stream)
		return nil
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	ap.addServiceTokenLinkHeader(w)

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		ap.stopStream(stream)
		return nil
	}

	// Relay stream line-by-line (flush after each write)
	reader := bufio.NewReader(upRes.Body)
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			if _, werr := w.Write(line); werr != nil {
				if isContextCanceledError(werr) {
					logrus.Debug("Client closed SSE connection")
					ap.stopStream(stream)
					return nil
				}
				logrus.WithError(werr).Warn("Write to client failed")
				ap.stopStream(stream)
				return nil
			}
			flusher.Flush()
		}
		if err != nil {
			if err == io.EOF || isContextCanceledError(err) {
				logrus.Debug("Upstream SSE closed")
				ap.stopStream(stream)
				return nil
			}
			logrus.WithError(err).Warn("Upstream SSE read error")
			ap.stopStream(stream)
			return nil
		}
	}
}

func (ap *AuthProxy) proxyToBackend(w http.ResponseWriter, r *http.Request, registration *ResourceRegistration, relPath string, addServiceLink bool) error {
	// Compute preferred target via Kubernetes NodePort service when possible
	actorID, _, err := extractActorAndPath(r.URL.Path)
	if err != nil {
		actorID = ""
	}
	preferredHost := resolveServiceTarget(actorID)
	var targetHost string
	if preferredHost != "" {
		targetHost = preferredHost
	} else {
		// Fallback to registration PodIP/port (with loopback rewrite)
		targetHost = resolveTargetHost(registration.PodIP, registration.Port)
	}

	targetURL := &url.URL{Scheme: "http", Host: targetHost}
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.FlushInterval = 250 * time.Millisecond
	proxy.Transport = &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 90 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableCompression:    true,
	}
	serviceLink := fmt.Sprintf("<%s>; rel=\"service-token-endpoint\"", ap.endpointUrl)
	proxy.ModifyResponse = func(res *http.Response) error {
		// Ensure CORS headers present on proxied actor responses
		res.Header.Set("Access-Control-Allow-Origin", "*")
		res.Header.Set("Access-Control-Allow-Methods", "GET, POST, DELETE, HEAD, OPTIONS")
		res.Header.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept, Origin, Cache-Control, X-Requested-With, If-None-Match, Last-Event-ID")
		res.Header.Set("Access-Control-Expose-Headers", "ETag, Link")
		res.Header.Set("Access-Control-Max-Age", "600")
		if addServiceLink {
			res.Header.Add("Link", serviceLink)
		}
		return nil
	}
	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		if isContextCanceledError(err) {
			logrus.WithFields(logrus.Fields{
				"target": targetHost,
				"path":   relPath,
			}).Debug("Reverse proxy context canceled (client disconnected or deadline reached)")
			// Do not write a 502 for expected cancellations
			return
		}
		logrus.WithError(err).WithFields(logrus.Fields{
			"target": targetHost,
			"path":   relPath,
		}).Error("Reverse proxy error")
		rw.WriteHeader(http.StatusBadGateway)
	}

	backendPath := normalizeRelativePath(relPath)
	logrus.WithFields(logrus.Fields{"target": targetHost, "backend_path": backendPath}).Info("Proxying to backend")

	req := r.Clone(r.Context())
	// Avoid passing Authorization to the pod; auth is enforced at aggregator
	req.Header.Del("Authorization")
	req.URL.Scheme = targetURL.Scheme
	req.URL.Host = targetURL.Host
	req.Host = targetURL.Host
	req.URL.Path = backendPath
	req.URL.RawPath = backendPath

	proxy.ServeHTTP(w, req)
	return nil
}

// isContextCanceledError determines if the error is a benign cancellation/closure
func isContextCanceledError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, http.ErrAbortHandler) || errors.Is(err, net.ErrClosed) {
		return true
	}
	// Common transient/cancel strings from http transport
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "context canceled") || strings.Contains(msg, "request canceled") || strings.Contains(msg, "broken pipe") {
		return true
	}
	// EOF during SSE disconnects
	return errors.Is(err, io.EOF)
}

func extractActorAndPath(path string) (string, string, error) {
	trimmed := strings.TrimPrefix(path, "/")
	if trimmed == "" {
		return "", "", &streamError{Message: "Missing actor identifier", Status: http.StatusBadRequest}
	}

	parts := strings.SplitN(trimmed, "/", 2)
	actorID := parts[0]
	if actorID == "" {
		return "", "", &streamError{Message: "Missing actor identifier", Status: http.StatusBadRequest}
	}

	relative := "/"
	if len(parts) == 2 && parts[1] != "" {
		relative = "/" + parts[1]
	}

	return actorID, relative, nil
}

func resolveRegisteredResource(actorID, relPath string) (*ResourceRegistration, string, error) {
	normalized := normalizeRelativePath(relPath)
	resourceKey := actorID + normalized
	if registration, ok := registeredResources[resourceKey]; ok {
		return registration, normalized, nil
	}

	var (
		bestMatch     *ResourceRegistration
		bestEndpoint  string
		targetPathLen int
	)

	for key, registration := range registeredResources {
		if !strings.HasPrefix(key, actorID) {
			continue
		}
		endpoint := key[len(actorID):]
		if endpoint == "" {
			endpoint = "/"
		}
		endpoint = normalizeRelativePath(endpoint)
		if strings.HasPrefix(normalized, endpoint) && len(endpoint) > targetPathLen {
			bestMatch = registration
			bestEndpoint = endpoint
			targetPathLen = len(endpoint)
		}
	}

	if bestMatch != nil {
		return bestMatch, bestEndpoint, nil
	}

	return nil, "", &streamError{
		Message: fmt.Sprintf("Resource %s not registered for actor %s", normalized, actorID),
		Status:  http.StatusNotFound,
	}
}

func normalizeRelativePath(path string) string {
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		return "/" + path
	}
	return path
}

func (ap *AuthProxy) addServiceTokenLinkHeader(w http.ResponseWriter) {
	w.Header().Add("Link", fmt.Sprintf("<%s>; rel=\"service-token-endpoint\"", ap.endpointUrl))
	// Also ensure CORS headers remain (some reverse proxy flows may overwrite)
	if w.Header().Get("Access-Control-Allow-Origin") == "" {
		setCORSProxy(w)
	}
}

// resolveServiceTarget tries to resolve id-<actorID>-service NodePort endpoint as nodeIP:nodePort
func resolveServiceTarget(actorID string) string {
	id := strings.TrimSpace(actorID)
	if id == "" {
		return ""
	}
	serviceName := "id-" + id + "-service"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	svc, err := Clientset.CoreV1().Services("default").Get(ctx, serviceName, metav1.GetOptions{})
	if err != nil || svc == nil || len(svc.Spec.Ports) == 0 {
		return ""
	}
	// Pick first NodePort > 0
	nodePort := int32(0)
	for _, p := range svc.Spec.Ports {
		if p.NodePort > 0 {
			nodePort = p.NodePort
			break
		}
	}
	if nodePort == 0 {
		return ""
	}
	// Choose a node IP (prefer External, then Internal)
	nodeIP := getClusterNodeIP(ctx)
	if nodeIP == "" {
		return ""
	}
	return fmt.Sprintf("%s:%d", nodeIP, nodePort)
}

func getClusterNodeIP(ctx context.Context) string {
	nodes, err := Clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil || nodes == nil || len(nodes.Items) == 0 {
		return ""
	}
	for _, node := range nodes.Items {
		for _, addr := range node.Status.Addresses {
			if addr.Type == "ExternalIP" {
				if strings.TrimSpace(addr.Address) != "" {
					return addr.Address
				}
			}
		}
	}
	for _, node := range nodes.Items {
		for _, addr := range node.Status.Addresses {
			if addr.Type == "InternalIP" {
				if strings.TrimSpace(addr.Address) != "" {
					return addr.Address
				}
			}
		}
	}
	return ""
}

// resolveTargetHost returns host:port for the backend, rewriting loopback IPs to a reachable host
func resolveTargetHost(podIP string, port int) string {
	host := strings.TrimSpace(podIP)
	if host == "" {
		host = "127.0.0.1"
	}
	lower := strings.ToLower(host)
	if lower == "127.0.0.1" || lower == "localhost" {
		if env := strings.TrimSpace(os.Getenv("HOST_IP")); env != "" {
			// Allow explicit override for host reachability
			host = env
		} else {
			// Fallback commonly available in minikube/docker (only if HOST_IP not set)
			host = "host.minikube.internal"
		}
	}
	return fmt.Sprintf("%s:%d", host, port)
}
