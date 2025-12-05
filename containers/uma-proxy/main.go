package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/sirupsen/logrus"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// FetchRequest represents the JSON payload for the /fetch endpoint
type FetchRequest struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

var caCert *x509.Certificate
var caKey *rsa.PrivateKey

func main() {
	webId := os.Getenv("WEBID")
	email := os.Getenv("EMAIL")
	password := os.Getenv("PASSWORD")
	var err error
	logLevel, err := logrus.ParseLevel(os.Getenv("LOG_LEVEL"))
	if err != nil {
		logLevel = logrus.InfoLevel
		err = nil
	}
	logrus.SetLevel(logLevel)
	logrus.SetOutput(os.Stdout)

	if webId != "" && email != "" && password != "" {
		logrus.WithFields(logrus.Fields{"webid": webId}).Info("🔐 Initializing Solid OIDC authentication")
		solidAuth = NewSolidAuth(webId)
		if err := solidAuth.Init(email, password); err != nil {
			logrus.WithFields(logrus.Fields{"err": err}).Error("⚠️ Failed to initialize Solid OIDC auth")
			logrus.Warn("⚠️ Continuing without Solid OIDC authentication")
			solidAuth = nil
		} else {
			logrus.Info("✅ Solid OIDC authentication initialized successfully")
		}
	} else {
		logrus.Warn("⚠️ WEBID, EMAIL, and/or PASSWORD not set")
		logrus.Warn("⚠️ Solid OIDC disabled - proxy will not perform authentication")
	}

	http.HandleFunc("/", Handler)
	http.HandleFunc("/fetch", FetchHandler)
	http.HandleFunc("/sse", SSEHandler)
	go func() {
		logrus.WithFields(logrus.Fields{"port": 8080}).Info("HTTP proxy listening")
		if err := http.ListenAndServe(":8080", nil); err != nil {
			logrus.WithFields(logrus.Fields{"err": err}).Error("HTTP proxy failed")
			os.Exit(1)
		}
	}()
	caCertPath := os.Getenv("CERT_PATH")
	caKeyPath := os.Getenv("KEY_PATH")

	caCert, caKey, err = loadCA(caCertPath, caKeyPath)
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("❌ Failed to load CA cert and key")
		os.Exit(1)
	}

	// HTTPS MITM proxy on 8443
	ln, err := net.Listen("tcp", ":8443")
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("Failed to start MITM listener")
		os.Exit(1)
	}
	defer ln.Close()
	logrus.WithFields(logrus.Fields{"port": 8443}).Info("🚀 HTTPS MITM proxy listening")

	for {
		conn, err := ln.Accept()
		if err != nil {
			logrus.WithFields(logrus.Fields{"err": err}).Warn("Accept error")
			continue
		}
		go handleMITM(conn)
	}
}

// Handler for HTTP UMA flow
func Handler(w http.ResponseWriter, req *http.Request) {
	logrus.WithFields(logrus.Fields{"method": req.Method, "request_uri": req.RequestURI}).Info("Request received")

	outReq, err := http.NewRequest(req.Method, req.RequestURI, req.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	for key, value := range req.Header {
		if key == "Authorization" {
			continue
		}
		for _, element := range value {
			outReq.Header.Add(key, element)
		}
	}

	resp, err := Do(outReq)
	if err != nil {
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for key, value := range resp.Header {
		w.Header()[key] = value
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
	location, _ := resp.Location()
	logrus.WithFields(logrus.Fields{"location": location, "status": resp.Status}).Info("Response delivered")
}

// Handler for /fetch endpoint
func FetchHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var fetchReq FetchRequest
	err := json.NewDecoder(r.Body).Decode(&fetchReq)
	if err != nil {
		http.Error(w, "Bad request: "+err.Error(), http.StatusBadRequest)
		return
	}

	logrus.WithFields(logrus.Fields{"method": fetchReq.Method, "url": fetchReq.URL}).Info("📡 Fetch request")

	// Parse the original URL to preserve the original host header
	originalURL, err := url.Parse(fetchReq.URL)
	if err != nil {
		http.Error(w, "Invalid URL: "+err.Error(), http.StatusBadRequest)
		return
	}
	originalHost := originalURL.Host
	originalURLStr := fetchReq.URL

	// Redirect localhost URLs to host machine
	fetchReq.URL = redirectLocalhostURL(fetchReq.URL)

	// Set default method if not provided
	if fetchReq.Method == "" {
		fetchReq.Method = "GET"
	}

	// Create request body reader if body is provided
	var bodyReader io.Reader
	if fetchReq.Body != "" {
		bodyReader = strings.NewReader(fetchReq.Body)
	}

	// Create new HTTP request
	req, err := http.NewRequest(fetchReq.Method, fetchReq.URL, bodyReader)
	if err != nil {
		http.Error(w, "Failed to create request: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Add headers to the request
	for key, value := range fetchReq.Headers {
		req.Header.Set(key, value)
	}

	// If we redirected a localhost URL, set the Host header to the original localhost value
	if fetchReq.URL != originalURLStr && strings.HasPrefix(originalHost, "localhost") {
		req.Host = originalHost
		logrus.WithFields(logrus.Fields{"original_host": originalHost}).Debug("🔧 Setting Host header to original value")
	}

	// Send the request using the Do function (which handles UMA flow)
	resp, err := Do(req)
	if err != nil {
		logrus.WithFields(logrus.Fields{"url": fetchReq.URL, "err": err}).Error("❌ Failed to fetch URL")
		http.Error(w, "Failed to fetch URL: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	logrus.WithFields(logrus.Fields{"url": fetchReq.URL, "status_code": resp.StatusCode, "status": resp.Status}).Info("✅ Response received")

	// Copy response headers to our response
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Set the status code
	w.WriteHeader(resp.StatusCode)

	// Copy the response body directly
	io.Copy(w, resp.Body)
}

// Handler for /sse endpoint - authenticates SSE connections and proxies the stream
func SSEHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var sseReq struct {
		URL string `json:"url"`
	}
	err := json.NewDecoder(r.Body).Decode(&sseReq)
	if err != nil {
		http.Error(w, "Bad request: "+err.Error(), http.StatusBadRequest)
		return
	}

	if sseReq.URL == "" {
		http.Error(w, "Bad request: url is required", http.StatusBadRequest)
		return
	}

	logrus.WithFields(logrus.Fields{"url": sseReq.URL}).Info("📡 SSE connection request")

	if solidAuth == nil {
		http.Error(w, "Authentication not configured", http.StatusServiceUnavailable)
		return
	}

	originalURL := sseReq.URL
	redirectedURL := redirectLocalhostURL(sseReq.URL)

	// Step 1: Initial request to get UMA challenge
	initialReq, err := http.NewRequest("GET", redirectedURL, nil)
	if err != nil {
		http.Error(w, "Failed to create request: "+err.Error(), http.StatusBadRequest)
		return
	}
	initialReq.Header.Set("Accept", "text/event-stream")

	if redirectedURL != originalURL {
		parsedOriginal, _ := url.Parse(originalURL)
		if parsedOriginal != nil {
			initialReq.Host = parsedOriginal.Host
		}
	}

	initialResp, err := throttledDo(initialReq)
	if err != nil {
		logrus.WithFields(logrus.Fields{"url": sseReq.URL, "err": err}).Error("❌ Failed to connect to SSE")
		http.Error(w, "Failed to connect: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer initialResp.Body.Close()

	if initialResp.StatusCode != http.StatusUnauthorized {
		logrus.WithFields(logrus.Fields{"status": initialResp.StatusCode}).Error("❌ Expected 401 for SSE, got different status")
		http.Error(w, fmt.Sprintf("Expected 401 for SSE authentication, got %d", initialResp.StatusCode), http.StatusBadGateway)
		return
	}

	// Step 2: Parse UMA challenge
	asUri, ticket, err := getTicketInfo(initialResp.Header.Get("WWW-Authenticate"))
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("❌ Failed to parse WWW-Authenticate header")
		http.Error(w, "Failed to parse UMA challenge: "+err.Error(), http.StatusBadGateway)
		return
	}

	// Step 3: Extract service endpoint from Link header
	linkHeader := initialResp.Header.Get("Link")
	serviceEndpoint := ""
	if linkHeader != "" {
		// Parse Link header: <url>; rel="service-token-endpoint"
		parts := strings.Split(linkHeader, ";")
		for i, part := range parts {
			if strings.Contains(part, `rel="service-token-endpoint"`) && i > 0 {
				urlPart := strings.TrimSpace(parts[i-1])
				urlPart = strings.Trim(urlPart, "<>")
				serviceEndpoint = urlPart
				break
			}
		}
	}

	if serviceEndpoint == "" {
		logrus.Error("❌ Missing service-token-endpoint in Link header")
		http.Error(w, "Missing UMA service endpoint for SSE", http.StatusBadGateway)
		return
	}

	logrus.WithFields(logrus.Fields{"as_uri": asUri, "service_endpoint": serviceEndpoint}).Debug("🔐 Retrieved UMA endpoints")

	// Step 4: Get UMA2 token endpoint
	uma2ConfigReq, err := createRequestWithRedirect("GET", asUri+"/.well-known/uma2-configuration", nil)
	if err != nil {
		http.Error(w, "Failed to create UMA config request: "+err.Error(), http.StatusBadGateway)
		return
	}

	uma2ConfigResp, err := throttledDo(uma2ConfigReq)
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("❌ Failed to get UMA2 configuration")
		http.Error(w, "Failed to get UMA2 configuration: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer uma2ConfigResp.Body.Close()

	if uma2ConfigResp.StatusCode != http.StatusOK {
		logrus.WithFields(logrus.Fields{"status": uma2ConfigResp.StatusCode}).Error("❌ UMA2 configuration request failed")
		http.Error(w, "UMA2 configuration unavailable", http.StatusBadGateway)
		return
	}

	var uma2Config struct {
		TokenEndpoint string `json:"token_endpoint"`
	}
	if err := json.NewDecoder(uma2ConfigResp.Body).Decode(&uma2Config); err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("❌ Failed to decode UMA2 configuration")
		http.Error(w, "Failed to decode UMA2 configuration: "+err.Error(), http.StatusBadGateway)
		return
	}

	tokenEndpoint := uma2Config.TokenEndpoint

	// Step 5: Get access token with claim gathering
	accessToken, tokenType, _, _, err := fetchAccessToken(tokenEndpoint, ticket, nil)
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("❌ Failed to fetch access token")
		http.Error(w, "Failed to fetch access token: "+err.Error(), http.StatusBadGateway)
		return
	}

	// Step 6: Get service token for SSE
	serviceToken, err := solidAuth.GetServiceToken(sseReq.URL, serviceEndpoint, tokenType, accessToken)
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("❌ Failed to get service token")
		http.Error(w, "Failed to get service token: "+err.Error(), http.StatusBadGateway)
		return
	}

	logrus.WithFields(logrus.Fields{"url": sseReq.URL}).Info("✅ Service token obtained")

	// Step 7: Connect to SSE with service token
	sseReq2, err := http.NewRequest("GET", redirectedURL, nil)
	if err != nil {
		http.Error(w, "Failed to create authenticated SSE request: "+err.Error(), http.StatusBadGateway)
		return
	}
	sseReq2.Header.Set("Accept", "text/event-stream")
	sseReq2.Header.Set("Cache-Control", "no-cache")
	sseReq2.Header.Set("Authorization", "Bearer "+serviceToken)

	if redirectedURL != originalURL {
		parsedOriginal, _ := url.Parse(originalURL)
		if parsedOriginal != nil {
			sseReq2.Host = parsedOriginal.Host
		}
	}

	sseResp, err := throttledDo(sseReq2)
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("❌ Failed to connect to authenticated SSE")
		http.Error(w, "Failed to connect to SSE: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer sseResp.Body.Close()

	if sseResp.StatusCode != http.StatusOK {
		bodyText, _ := io.ReadAll(sseResp.Body)
		logrus.WithFields(logrus.Fields{"status": sseResp.StatusCode, "body": string(bodyText)}).Error("❌ SSE connection failed")
		http.Error(w, fmt.Sprintf("SSE connection failed (status: %d): %s", sseResp.StatusCode, string(bodyText)), http.StatusBadGateway)
		return
	}

	logrus.WithFields(logrus.Fields{"url": sseReq.URL}).Info("✅ SSE connection established, streaming")

	// Step 8: Set up SSE response headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// Copy any other relevant headers from upstream
	for key, values := range sseResp.Header {
		if key != "Content-Type" && key != "Cache-Control" && key != "Connection" {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
	}

	w.WriteHeader(http.StatusOK)

	// Flush headers immediately
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	// Step 9: Stream the SSE data
	buf := make([]byte, 4096)
	for {
		n, err := sseResp.Body.Read(buf)
		if n > 0 {
			_, writeErr := w.Write(buf[:n])
			if writeErr != nil {
				logrus.WithFields(logrus.Fields{"err": writeErr}).Warn("⚠️ Failed to write SSE data to client")
				return
			}
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
		}
		if err == io.EOF {
			logrus.WithFields(logrus.Fields{"url": sseReq.URL}).Info("📭 SSE stream ended")
			return
		}
		if err != nil {
			logrus.WithFields(logrus.Fields{"err": err}).Warn("⚠️ Error reading SSE stream")
			return
		}
	}
}

// MITM handler
func handleMITM(conn net.Conn) {
	defer conn.Close()
	connReader := bufio.NewReader(conn)

	req, err := http.ReadRequest(connReader)
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("❌ Failed to parse CONNECT request")
		return
	}

	if req.Method != http.MethodConnect {
		logrus.Warn("❌ Non-CONNECT request received on MITM listener, ignoring")
		return
	}

	targetHost, _, err := net.SplitHostPort(req.Host)
	if err != nil {
		targetHost = req.Host // fallback if no port
	}
	logrus.WithFields(logrus.Fields{"host": targetHost}).Info("🔌 Intercepting CONNECT")

	fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")

	// Generate cert for target
	certPEM, keyPEM, err := generateCert(targetHost)
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("❌ Failed to generate MITM cert")
		return
	}
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("❌ X509KeyPair error")
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}
	tlsConn := tls.Server(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("❌ TLS handshake error")
		return
	}
	defer tlsConn.Close()

	tlsReader := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(tlsReader)
		if err != nil {
			if err == io.EOF {
				return
			}
			logrus.WithFields(logrus.Fields{"err": err}).Error("❌ Failed to read decrypted request")
			return
		}

		req.URL.Scheme = "https"
		req.URL.Host = req.Host

		logrus.WithFields(logrus.Fields{"method": req.Method, "url": req.URL.String()}).Debug("➡️ MITM request")

		outReq, err := http.NewRequest(req.Method, req.URL.String(), req.Body)
		if err != nil {
			sendError(tlsConn, http.StatusBadRequest, "bad request")
			return
		}

		for key, value := range req.Header {
			if key == "Authorization" {
				continue
			}
			for _, element := range value {
				outReq.Header.Add(key, element)
			}
		}

		resp, err := Do(outReq) // UMA flow
		if err != nil {
			sendError(tlsConn, http.StatusBadGateway, "upstream error: "+err.Error())
			return
		}
		defer resp.Body.Close()

		err = resp.Write(tlsConn)
		if err != nil {
			logrus.WithFields(logrus.Fields{"err": err}).Error("❌ Failed to write back to client")
			return
		}
	}
}

// Helper: send raw HTTP error over conn
func sendError(w io.Writer, statusCode int, message string) {
	statusText := http.StatusText(statusCode)
	body := fmt.Sprintf("%d %s: %s", statusCode, statusText, message)
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s",
		statusCode, statusText, len(body), body)
}

// Load your internal CA cert and key
func loadCA(certFile, keyFile string) (*x509.Certificate, *rsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, err
	}
	block, _ = pem.Decode(keyPEM)
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("not an RSA private key")
	}
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

// Dynamically generate cert for target host signed by internal CA
func generateCert(host string) ([]byte, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(1, 0, 0),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames: []string{host},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return certPEM, keyPEM, nil
}

// hostCandidateOK checks if a hostname/IP resolves (if needed) and optionally accepts TCP connections on port with a short timeout.
func hostCandidateOK(host string, port string) bool {
	// Quick DNS check for hostnames
	if net.ParseIP(host) == nil {
		if _, err := net.LookupIP(host); err != nil {
			return false
		}
	}
	// If we have a port, try a very short TCP dial to ensure reachability
	if strings.TrimSpace(port) != "" {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 300*time.Millisecond)
		if err != nil {
			return false
		}
		_ = conn.Close()
	}
	return true
}

// getReachableHostForLocal returns a host alias or IP on which the given port appears reachable from this container.
// Preference order: env overrides -> host.docker.internal -> host.containers.internal -> common docker bridges.
func getReachableHostForLocal(port string) string {
	// 1) Environment overrides
	for _, key := range []string{"HOST_IP", "KIND_NODE_IP", "NODE_IP", "KUBERNETES_NODE_IP"} {
		val := strings.TrimSpace(os.Getenv(key))
		if val != "" && hostCandidateOK(val, port) {
			logrus.WithFields(logrus.Fields{"host": val, "source": key}).Info("Using host override for localhost redirection")
			return val
		}
	}

	// 2) Well-known hostnames in containerized envs
	for _, cand := range []string{"host.docker.internal", "host.containers.internal"} {
		if hostCandidateOK(cand, port) {
			logrus.WithFields(logrus.Fields{"host": cand}).Info("Using container host alias for localhost redirection")
			return cand
		}
	}

	// 3) Common Docker bridge gateways
	for _, ip := range []string{"172.17.0.1", "172.18.0.1"} {
		if hostCandidateOK(ip, port) {
			logrus.WithFields(logrus.Fields{"host": ip}).Info("Using Docker bridge gateway for localhost redirection")
			return ip
		}
	}

	// 4) Fallback to host.docker.internal without probing (may still work if DNS provided externally)
	return "host.docker.internal"
}

// redirectLocalhostURL converts localhost URLs and known host aliases to a host/IP reachable from this container
func redirectLocalhostURL(originalURL string) string {
	parsedURL, err := url.Parse(originalURL)
	if err != nil {
		return originalURL
	}

	hostname := parsedURL.Hostname()
	// Determine target port (empty means default for scheme)
	port := parsedURL.Port()
	if port == "" {
		if strings.EqualFold(parsedURL.Scheme, "https") {
			port = "443"
		} else {
			port = "80"
		}
	}

	// Localhost handling
	if hostname == "localhost" || hostname == "127.0.0.1" {
		cand := getReachableHostForLocal(port)
		parsedURL.Host = net.JoinHostPort(cand, port)
		redirectedURL := parsedURL.String()
		logrus.WithFields(logrus.Fields{"original_url": originalURL, "redirected_url": redirectedURL}).Debug("🔄 Redirecting localhost URL")
		return redirectedURL
	}

	// Known host aliases that might not resolve inside kind/Linux
	if hostname == "host.docker.internal" || hostname == "host.containers.internal" || hostname == "docker.for.mac.host.internal" || hostname == "docker.for.win.localhost" {
		if hostCandidateOK(hostname, port) {
			// Alias works, no change
			return originalURL
		}
		// Pick an alternative reachable host
		cand := getReachableHostForLocal(port)
		if cand != hostname {
			parsedURL.Host = net.JoinHostPort(cand, port)
			redirectedURL := parsedURL.String()
			logrus.WithFields(logrus.Fields{"original_url": originalURL, "redirected_url": redirectedURL}).Info("🔄 Remapping host alias to reachable host for kind/docker")
			return redirectedURL
		}
	}

	return originalURL
}

// createRequestWithRedirect creates an HTTP request with URL reachability normalization and Host header preservation
func createRequestWithRedirect(method, urlStr string, body io.Reader) (*http.Request, error) {
	redirectedURL := redirectLocalhostURL(urlStr)

	req, err := http.NewRequest(method, redirectedURL, body)
	if err != nil {
		return nil, err
	}

	// Preserve original Host header if redirected
	if redirectedURL != urlStr {
		originalURL, err := url.Parse(urlStr)
		if err == nil && originalURL != nil {
			req.Host = originalURL.Host
		}
	}

	return req, nil
}
