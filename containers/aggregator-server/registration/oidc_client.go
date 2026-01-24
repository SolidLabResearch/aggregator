package registration

import (
	"aggregator/model"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
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

	if cfg.AuthorizationEndpoint == "" || cfg.TokenEndpoint == "" {
		return nil, fmt.Errorf("OIDC config missing required endpoints")
	}

	return &cfg, nil
}

const (
	tokenAuthMethodClientSecretBasic = "client_secret_basic"
	tokenAuthMethodClientSecretPost  = "client_secret_post"
)

func doTokenRequest(endpoint string, supportedMethods []string, data url.Values, clientID string, clientSecret string) (*http.Response, error) {
	method := selectTokenAuthMethod(supportedMethods)
	req, err := buildTokenRequest(endpoint, method, data, clientID, clientSecret)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	return client.Do(req)
}

func selectTokenAuthMethod(supportedMethods []string) string {
	if len(supportedMethods) == 0 {
		return tokenAuthMethodClientSecretBasic
	}

	for _, method := range supportedMethods {
		switch strings.ToLower(method) {
		case tokenAuthMethodClientSecretBasic:
			return tokenAuthMethodClientSecretBasic
		case tokenAuthMethodClientSecretPost:
			return tokenAuthMethodClientSecretPost
		}
	}

	return tokenAuthMethodClientSecretBasic
}

func buildTokenRequest(endpoint string, authMethod string, data url.Values, clientID string, clientSecret string) (*http.Request, error) {
	if authMethod == "" {
		authMethod = tokenAuthMethodClientSecretBasic
	}

	switch authMethod {
	case tokenAuthMethodClientSecretPost:
		data.Set("client_id", clientID)
		data.Set("client_secret", clientSecret)
	case tokenAuthMethodClientSecretBasic:
		data.Del("client_id")
		data.Del("client_secret")
	default:
		return nil, fmt.Errorf("unsupported token auth method: %s", authMethod)
	}

	encoded := data.Encode()
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBufferString(encoded))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if authMethod == tokenAuthMethodClientSecretBasic {
		credentials := clientID + ":" + clientSecret
		basic := base64.StdEncoding.EncodeToString([]byte(credentials))
		req.Header.Set("Authorization", "Basic "+basic)
	}

	return req, nil
}
