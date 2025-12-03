package registration

import (
	"aggregator/types"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

var stateStore = make(map[string]types.RegistrationRequest) // state to as_url mapping

func generateRandomState() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
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

func getTokenEndpoint(issuer string) (string, error) {
	url := fmt.Sprintf("%s/.well-known/openid-configuration", issuer)

	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to fetch OIDC config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("OIDC config error: %s", string(body))
	}

	var config struct {
		TokenEndpoint string `json:"token_endpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return "", fmt.Errorf("failed to parse OIDC config: %w", err)
	}

	if config.TokenEndpoint == "" {
		return "", fmt.Errorf("token_endpoint not found in OIDC config")
	}

	return config.TokenEndpoint, nil
}

func getAuthEndpoint(issuer string) (string, error) {
	url := fmt.Sprintf("%s/.well-known/openid-configuration", issuer)

	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to fetch OIDC config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("OIDC config error: %s", string(body))
	}

	var config struct {
		AuthnEndpoint string `json:"authorization_endpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return "", fmt.Errorf("failed to parse OIDC config: %w", err)
	}

	if config.AuthnEndpoint == "" {
		return "", fmt.Errorf("authorization_endpoint not found in OIDC config")
	}

	return config.AuthnEndpoint, nil
}
