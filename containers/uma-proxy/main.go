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
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
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
	http.HandleFunc("/", Handler)
	http.HandleFunc("/fetch", FetchHandler)
	go func() {
		log.Println("HTTP proxy listening on port: 8080")
		log.Fatal(http.ListenAndServe(":8080", nil))
	}()
	caCertPath := os.Getenv("CERT_PATH")
	caKeyPath := os.Getenv("KEY_PATH")

	var err error
	caCert, caKey, err = loadCA(caCertPath, caKeyPath)
	if err != nil {
		log.Fatalf("❌ Failed to load CA cert and key: %v", err)
	}

	// HTTPS MITM proxy on 8443
	ln, err := net.Listen("tcp", ":8443")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	log.Println("🚀 HTTPS MITM proxy listening on port: 8443")

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("Accept error:", err)
			continue
		}
		go handleMITM(conn)
	}
}

// TODO add a cache to the proxy
// Handler for HTTP UMA flow
func Handler(w http.ResponseWriter, req *http.Request) {
	fmt.Println("Request received", req.Method, req.RequestURI)

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
	fmt.Println("Response", location, resp.Status)
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

	log.Printf("📡 Fetch request: %s %s", fetchReq.Method, fetchReq.URL)

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

	// Send the request using the Do function (which handles UMA flow)
	resp, err := Do(req)
	if err != nil {
		log.Printf("❌ Failed to fetch %s: %v", fetchReq.URL, err)
		http.Error(w, "Failed to fetch URL: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	log.Printf("✅ Response from %s: %d %s", fetchReq.URL, resp.StatusCode, resp.Status)

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
		log.Println("❌ Failed to parse CONNECT request:", err)
		return
	}

	if req.Method != http.MethodConnect {
		log.Println("❌ Non-CONNECT request received on MITM listener, ignoring")
		return
	}

	targetHost, _, err := net.SplitHostPort(req.Host)
	if err != nil {
		targetHost = req.Host // fallback if no port
	}
	log.Println("🔌 Intercepting CONNECT to:", targetHost)

	fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")

	// Generate cert for target
	certPEM, keyPEM, err := generateCert(targetHost)
	if err != nil {
		log.Println("❌ Failed to generate MITM cert:", err)
		return
	}
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Println("❌ X509KeyPair error:", err)
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}
	tlsConn := tls.Server(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		log.Println("❌ TLS handshake error:", err)
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
			log.Println("❌ Failed to read decrypted request:", err)
			return
		}

		req.URL.Scheme = "https"
		req.URL.Host = req.Host

		log.Println("➡️ MITM request:", req.Method, req.URL.String())

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
			log.Println("❌ Failed to write back to client:", err)
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
