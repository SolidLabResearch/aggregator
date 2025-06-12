package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"
)

var (
	// We'll keep a single RSA key in this demo.
	// In production, you might manage multiple keys for rotation.
	rsaPrivateKey *rsa.PrivateKey

	// We'll store the JWKS (with the public part of the above key).
	myJWKS Jwks

	// We'll define a KID (key ID) so verifiers know which key to use.
	keyID = "demo-key-1"
)

// Jwk represents a single JSON Web Key in a JWKS.
type Jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"` // Modulus (base64url)
	E   string `json:"e"` // Exponent (base64url)
}

// Jwks is a JSON Web Key Set.
type Jwks struct {
	Keys []Jwk `json:"keys"`
}

func InitSigning(mux *http.ServeMux) {
	// 1) Load our RSA private key from file (PEM).
	setPrivateKey("private_key.pem")

	// 2) Build a JWKS entry for the **public** part of our RSA key.
	//    We'll serve this at /.well-known/jwks.json so verifiers can fetch it.
	pubJwk, err := makeJWKFromRSAPrivateKey(keyID)
	if err != nil {
		log.Fatalf("Failed to create JWK: %v", err)
	}
	myJWKS = Jwks{Keys: []Jwk{pubJwk}}

	// 3) Start a small HTTP server that hosts our JWKS.
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		println("Serving JWKS")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(myJWKS)
	})
}

func setPrivateKey(keyFilePath string) {
	if rsaPrivateKey != nil {
		return
	}

	// Check if key is stored in file
	if _, err := os.Stat(keyFilePath); err == nil {
		// Read the key from the file
		keyData, err := os.ReadFile(keyFilePath)
		if err != nil {
			fmt.Println("Error reading RSA key from file: ", err)
			return
		}

		block, _ := pem.Decode(keyData)
		if block == nil || block.Type != "RSA PRIVATE KEY" {
			fmt.Println("Failed to decode PEM block containing RSA private key")
			return
		}

		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			fmt.Println("Error parsing RSA private key: ", err)
			return
		}

		rsaPrivateKey = key
		return
	}

	// If not, generate new key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Error generating RSA key: ", err)
		return
	}
	rsaPrivateKey = key

	// Store generated key in file
	keyData := x509.MarshalPKCS1PrivateKey(key)
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyData,
	})

	err = os.WriteFile(keyFilePath, pemData, 0600)
	if err != nil {
		fmt.Println("Error writing RSA key to file: ", err)
		return
	}
	return
}

// makeJWKFromRSAPrivateKey produces a Jwk containing the public portion
// (n, e) for the given RSA key, along with a provided kid.
func makeJWKFromRSAPrivateKey(kid string) (Jwk, error) {
	pub := rsaPrivateKey.Public().(*rsa.PublicKey)
	// Convert modulus (N) and exponent (E) to base64url
	nBytes := pub.N.Bytes()
	eBytes := big.NewInt(int64(pub.E)).Bytes()

	// Base64-URL encode without padding
	nStr := base64.RawURLEncoding.EncodeToString(nBytes)
	eStr := base64.RawURLEncoding.EncodeToString(eBytes)

	// Create JWK struct
	jwk := Jwk{
		Kty: "RSA",
		Kid: kid,
		Use: "sig",
		Alg: "RS256", // or RS384/RS512 etc. if you prefer
		N:   nStr,
		E:   eStr,
	}
	return jwk, nil
}

func doSignedRequest(req *http.Request) (*http.Response, error) {
	// 1) Put your domain in the Authorization header as cred="..."
	//    The Node server uses that to fetch your JWK from JWKS
	req.Header.Set("Authorization", fmt.Sprintf(`HttpSig cred=%q`, "http://localhost:5000"))

	label := "sig1"

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read body of outgoing request: %w", err)
	}
	h := sha256.Sum256(body)
	digestVal := "sha-256=" + base64.StdEncoding.EncodeToString(h[:])
	req.Header.Set("Content-Digest", digestVal)

	dateVal := time.Now().UTC().Format(http.TimeFormat)
	req.Header.Set("Date", dateVal)

	created := time.Now().Unix()
	signatureInputValue := fmt.Sprintf(
		`%s=("content-digest" "date");keyid=%q;alg=%q;created=%d`,
		label, keyID, "RS256", created,
	)
	req.Header.Set("Signature-Input", signatureInputValue)

	canonical := fmt.Sprintf(
		"\"content-digest\": %s\n\"date\": %s\n\"@signature-params\": (\"content-digest\" \"date\");keyid=%q;alg=%q;created=%d",
		digestVal,
		dateVal,
		keyID,
		"RS256",
		created,
	)

	hash := sha256.Sum256([]byte(canonical))
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, crypto.SHA256, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	sigB64 := base64.StdEncoding.EncodeToString(sigBytes)
	signatureValue := fmt.Sprintf(`%s=:%s:`, label, sigB64)

	req.Header.Set("Signature", signatureValue)

	client := &http.Client{}
	return client.Do(req)
}
