package registration

import (
	"aggregator/model"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

type storedState struct {
	Req       model.RegistrationRequest
	ExpiresAt time.Time
}

var (
	stateStore   = make(map[string]storedState)
	stateStoreMu sync.Mutex
)

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

// verifyToken verifies the JWT using the issuer's JWKS endpoint.
// Returns the parsed token if valid.
func verifyToken(tokenString string, issuer string) (jwt.Token, error) {
	// Build JWKS URL from issuer
	jwksURL := fmt.Sprintf("%s/protocol/openid-connect/certs", issuer)

	// Fetch JWKS from IdP
	keySet, err := jwk.Fetch(context.Background(), jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	// Parse and verify token using the key set
	token, err := jwt.Parse([]byte(tokenString), jwt.WithKeySet(keySet))
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	return token, nil
}

// validateToken checks standard claims of the token. and returns the user id if valid.
func validateToken(token jwt.Token, idp string) (string, error) {
	// Check expiration
	exp := token.Expiration()
	if time.Now().After(exp) {
		return "", fmt.Errorf("token has expired")
	}

	// Check issuer
	iss, ok := token.Get("iss")
	if !ok || iss.(string) != idp {
		return "", fmt.Errorf("invalid issuer")
	}
	// Extract user id (sub claim)
	sub, ok := token.Get("sub")
	if !ok {
		return "", fmt.Errorf("sub claim not found")
	}

	userID, ok := sub.(string)
	if !ok {
		return "", fmt.Errorf("invalid sub claim type")
	}

	return userID, nil
}
