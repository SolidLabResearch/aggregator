package registration

import (
	"aggregator/model"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type storedState struct {
	OwnerWebID          string
	AuthorizationServer string
	AggregatorID        string // empty for new, set for updates
	ClientID            string
	CodeVerifier        string
	IDPIssuer           string
	TokenEndpoint       string
	TokenEndpointAuthMethodsSupported []string
	ExpiresAt           time.Time
}

var (
	stateStore   = make(map[string]storedState)
	stateStoreMu sync.Mutex
)

func generatePKCE() (verifier string, challenge string, err error) {
	// 32 bytes = 43-character URL-safe string
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}

	// Code verifier (Base64 URL-safe, no padding)
	verifier = base64.RawURLEncoding.EncodeToString(b)

	// SHA256 hash of the verifier
	sum := sha256.Sum256([]byte(verifier))

	// Code challenge (Base64 URL-safe, no padding)
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])

	return verifier, challenge, nil
}

func generateRandomState() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// fetchOIDCConfig fetches and parses the OIDC discovery document for the given IdP
func fetchOIDCConfig(idpURL string) (*model.OIDCConfig, error) {
	discoveryURL := fmt.Sprintf("%s/.well-known/openid-configuration", idpURL)

	res, err := http.Get(discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OIDC discovery document: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OIDC discovery returned non-OK status: %s", res.Status)
	}

	var cfg model.OIDCConfig
	if err := json.NewDecoder(res.Body).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("failed to decode OIDC discovery JSON: %w", err)
	}

	if cfg.
		AuthorizationEndpoint == "" || cfg.TokenEndpoint == "" {
		return nil, fmt.Errorf("OIDC config missing required endpoints")
	}

	return &cfg, nil
}
