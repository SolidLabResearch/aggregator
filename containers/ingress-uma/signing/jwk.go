package signing

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"

	log "github.com/sirupsen/logrus"
)

var (
	rsaPrivateKey *rsa.PrivateKey
	myJWKS        Jwks
	keyID         string
	CredURI       string
)

// InitSigning initializes or loads the RSA key and attaches JWKS endpoint.
// keyFilePath: path to store/load private key
// mux: ServeMux to attach /.well-known/jwks.json
func InitSigning(mux *http.ServeMux, keyFilePath string, extHost string) {
	loadOrGenerateKey(keyFilePath)

	// Build JWKS from public key
	pubJwk, err := makeJWKFromRSAPrivateKey(keyID)
	if err != nil {
		log.WithError(err).Fatal("Failed to create JWK")
	}
	myJWKS = Jwks{Keys: []Jwk{pubJwk}}

	// Expose JWKS endpoint
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		log.Debug("Serving JWKS")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(myJWKS)
	})

	CredURI = "http://" + extHost + "/.well-known/jwks.json#" + keyID
}

// loadOrGenerateKey loads the RSA private key from disk or generates a new one.
// It also generates a stable keyID based on public key hash.
func loadOrGenerateKey(path string) {
	if _, err := os.Stat(path); err == nil {
		key, id := readPrivateKeyFromFile(path)
		rsaPrivateKey = key
		keyID = id
		log.Infof("Loaded RSA key with KID=%s", keyID)
		return
	}

	// Generate new key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.WithError(err).Fatal("Failed to generate RSA key")
	}
	rsaPrivateKey = key

	// Compute keyID from public key hash (stable)
	pubBytes := x509.MarshalPKCS1PublicKey(&rsaPrivateKey.PublicKey)
	hash := sha256.Sum256(pubBytes)
	keyID = fmt.Sprintf("%x", hash[:8]) // first 8 bytes of SHA256 hash

	// Save key to disk
	savePrivateKeyToFile(key, path)
	log.Infof("Generated new RSA key with KID=%s", keyID)
}

// readPrivateKeyFromFile loads a PEM-encoded RSA private key and computes KID
func readPrivateKeyFromFile(path string) (*rsa.PrivateKey, string) {
	data, err := os.ReadFile(path)
	if err != nil {
		log.WithError(err).Fatal("Failed to read private key file")
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		log.Fatal("Invalid PEM block in private key file")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.WithError(err).Fatal("Failed to parse RSA private key")
	}

	// Compute stable keyID
	pubBytes := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	hash := sha256.Sum256(pubBytes)
	kid := fmt.Sprintf("%x", hash[:8])

	return key, kid
}

// savePrivateKeyToFile writes PEM-encoded RSA key to disk
func savePrivateKeyToFile(key *rsa.PrivateKey, path string) {
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if err := os.WriteFile(path, pemData, 0600); err != nil {
		log.WithError(err).Fatal("Failed to write private key to file")
	}
}

// Jwk represents a JSON Web Key
type Jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// Jwks represents a JSON Web Key Set
type Jwks struct {
	Keys []Jwk `json:"keys"`
}

// makeJWKFromRSAPrivateKey builds a JWK with public part of RSA key
func makeJWKFromRSAPrivateKey(kid string) (Jwk, error) {
	pub := rsaPrivateKey.Public().(*rsa.PublicKey)
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())

	return Jwk{
		Kty: "RSA",
		Kid: kid,
		Use: "sig",
		Alg: "RS256",
		N:   n,
		E:   e,
	}, nil
}
