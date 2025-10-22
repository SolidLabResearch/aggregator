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
	redirectedURL, _ := url.Parse(fetchReq.URL)
	if redirectedURL.Hostname() == "host.minikube.internal" && (originalHost == "localhost:3000" || strings.HasPrefix(originalHost, "localhost:")) {
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

// getHostIP returns the host machine IP address for localhost redirection
func getHostIP() string {
	// Try to get host IP from environment variable first
	if hostIP := os.Getenv("HOST_IP"); hostIP != "" {
		logrus.WithFields(logrus.Fields{"host_ip": hostIP}).Info("Using HOST_IP from environment")
		return hostIP
	}

	// In minikube, try host.minikube.internal first
	logrus.Info("No HOST_IP set, trying host.minikube.internal")
	return "host.minikube.internal"
}

// redirectLocalhostURL converts localhost URLs to host machine IP
func redirectLocalhostURL(originalURL string) string {
	parsedURL, err := url.Parse(originalURL)
	if err != nil {
		return originalURL
	}

	// Check if it's a localhost URL
	if parsedURL.Hostname() == "localhost" || parsedURL.Hostname() == "127.0.0.1" {
		hostIP := getHostIP()
		parsedURL.Host = fmt.Sprintf("%s:%s", hostIP, parsedURL.Port())
		redirectedURL := parsedURL.String()
		logrus.WithFields(logrus.Fields{"original_url": originalURL, "redirected_url": redirectedURL}).Debug("🔄 Redirecting localhost URL")
		return redirectedURL
	}

	return originalURL
}

// createRequestWithRedirect creates an HTTP request with localhost URL redirection and Host header preservation
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
