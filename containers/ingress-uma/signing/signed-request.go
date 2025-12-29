package signing

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

// DoSignedRequest signs an HTTP request using the RS private key and HTTP signatures
// and sends it. It computes Content-Digest, Date, Signature-Input, and Signature headers.
//
// Parameters:
//   - req: the HTTP request to sign
//
// Returns the HTTP response or an error.
func DoSignedRequest(req *http.Request) (*http.Response, error) {
	if rsaPrivateKey == nil {
		return nil, fmt.Errorf("RSA private key not initialized")
	}

	// Step 1: Authorization header
	req.Header.Set("Authorization", fmt.Sprintf(`HttpSig cred=%q`, CredURI))

	// Step 2: Read body for digest
	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
	}
	// Reset Body so it can be read again
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// Step 3: Compute Content-Digest header
	hash := sha256.Sum256(bodyBytes)
	digestVal := "sha-256=" + base64.StdEncoding.EncodeToString(hash[:])
	req.Header.Set("Content-Digest", digestVal)

	// Step 4: Date header
	dateVal := time.Now().UTC().Format(http.TimeFormat)
	req.Header.Set("Date", dateVal)

	// Step 5: Signature-Input header
	label := "sig1"
	created := time.Now().Unix()
	sigInput := fmt.Sprintf(`%s=("content-digest" "date");keyid=%q;alg=%q;created=%d`,
		label, keyID, "RS256", created)
	req.Header.Set("Signature-Input", sigInput)

	// Step 6: Canonicalize headers for signing
	canonical := fmt.Sprintf(
		"\"content-digest\": %s\n\"date\": %s\n\"@signature-params\": (\"content-digest\" \"date\");keyid=%q;alg=%q;created=%d",
		digestVal, dateVal, keyID, "RS256", created,
	)

	// Step 7: Sign canonical string using RSA private key
	sigHash := sha256.Sum256([]byte(canonical))
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, crypto.SHA256, sigHash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}
	signatureValue := fmt.Sprintf(`%s=:%s:`, label, base64.StdEncoding.EncodeToString(sigBytes))
	req.Header.Set("Signature", signatureValue)

	// Step 8: Send HTTP request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.WithFields(log.Fields{
			"method": req.Method,
			"url":    req.URL.String(),
			"err":    err,
		}).Error("Signed request failed")
		return nil, err
	}

	log.WithFields(log.Fields{
		"method": req.Method,
		"url":    req.URL.String(),
		"status": resp.StatusCode,
		"keyID":  keyID,
		"label":  label,
		"rsCred": CredURI,
	}).Debug("Signed request sent successfully")

	return resp, nil
}
