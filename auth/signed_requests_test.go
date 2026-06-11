package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
)

func TestSignHTTPRequestUsesHttpSigTargetURIAndMethod(t *testing.T) {
	oldKey := rsaPrivateKey
	oldCredential := HTTP_SIGNATURE_CREDENTIAL
	oldKeyID := keyID
	t.Cleanup(func() {
		rsaPrivateKey = oldKey
		HTTP_SIGNATURE_CREDENTIAL = oldCredential
		keyID = oldKeyID
	})

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	rsaPrivateKey = key
	HTTP_SIGNATURE_CREDENTIAL = "http://aggregator.example"
	keyID = "test-key"

	request, err := http.NewRequest(http.MethodPost, "http://localhost:4581/resource-registration", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	if err := signHTTPRequest(request); err != nil {
		t.Fatalf("failed to sign request: %v", err)
	}

	if request.Header.Get("Authorization") != `HttpSig cred="http://aggregator.example"` {
		t.Fatalf("unexpected Authorization header: %q", request.Header.Get("Authorization"))
	}
	signatureInput := request.Header.Get("Signature-Input")
	if !strings.Contains(signatureInput, `sig=("@target-uri" "@method")`) {
		t.Fatalf("Signature-Input should cover @target-uri and @method, got %q", signatureInput)
	}
	if strings.Contains(signatureInput, "content-digest") || strings.Contains(signatureInput, "date") {
		t.Fatalf("Signature-Input should not use the old content-digest/date fields: %q", signatureInput)
	}

	created := signatureInput[strings.LastIndex(signatureInput, "created=")+len("created="):]
	canonical := "\"@target-uri\": http://localhost:4581/resource-registration\n" +
		"\"@method\": POST\n" +
		"\"@signature-params\": (\"@target-uri\" \"@method\");keyid=\"test-key\";alg=\"RS256\";created=" + created
	hash := sha256.Sum256([]byte(canonical))
	signature := strings.TrimPrefix(request.Header.Get("Signature"), "sig=:")
	signature = strings.TrimSuffix(signature, ":")
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		t.Fatalf("signature is not base64: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, hash[:], signatureBytes); err != nil {
		t.Fatalf("signature does not verify against expected base: %v", err)
	}
}
