package registration

import (
	"aggregator/model"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/sirupsen/logrus"
)

// TODO: add caching for JWKS keys to avoid fetching them on every request
// TODO: add support for DPOP tokens

// extractBearerToken extracts the bearer token from the Authorization header
func extractBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("missing Authorization header")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", errors.New("invalid Authorization header format")
	}

	return parts[1], nil
}

// authenticateRequest validates the IDP_client_token and extracts the WebID
func authenticateRequest(r *http.Request) (webID string, err error) {
	tokenString, err := extractBearerToken(r)
	if err != nil {
		return "", err
	}

	// If authentication is disabled (for testing), just parse and extract WebID without validation
	if model.DisableAuth {
		token, err := jwt.Parse([]byte(tokenString), jwt.WithValidate(false))
		if err != nil {
			return "", errors.New("invalid token format")
		}

		// Extract WebID from token
		if webidClaim, ok := token.Get("webid"); ok {
			if webidStr, ok := webidClaim.(string); ok {
				return webidStr, nil
			}
		}
		if sub, ok := token.Get("sub"); ok {
			if subStr, ok := sub.(string); ok {
				return subStr, nil
			}
		}
		return "", errors.New("no webid or sub claim in token")
	}

	// Production mode: full token validation
	// Parse token to extract issuer (needed to get JWKS URL)
	unverifiedToken, err := jwt.Parse([]byte(tokenString), jwt.WithValidate(false))
	if err != nil {
		logrus.WithError(err).Warn("Failed to parse IDP client token")
		return "", errors.New("invalid token format")
	}

	// Get issuer from token
	issuer, ok := unverifiedToken.Get("iss")
	if !ok {
		return "", errors.New("token missing issuer claim")
	}
	issuerStr, ok := issuer.(string)
	if !ok {
		return "", errors.New("invalid issuer claim")
	}

	// Construct JWKS URL from issuer
	// Try standard OIDC discovery first
	jwksURL, err := discoverJWKSURL(issuerStr)
	if err != nil {
		logrus.WithError(err).Warnf("Failed to discover JWKS URL for issuer %s", issuerStr)
		return "", errors.New("failed to discover JWKS endpoint")
	}

	// Verify token signature using JWKS
	verifiedToken, err := verifyTokenWithJWKS(tokenString, jwksURL)
	if err != nil {
		logrus.WithError(err).Warn("Token signature verification failed")
		return "", errors.New("invalid token signature")
	}

	// Validate token claims
	if err := validateTokenClaims(verifiedToken, issuerStr); err != nil {
		logrus.WithError(err).Warn("Token validation failed")
		return "", err
	}

	// Extract WebID from verified token
	// Try 'webid' claim first, then 'sub'
	if webidClaim, ok := verifiedToken.Get("webid"); ok {
		if webidStr, ok := webidClaim.(string); ok {
			return webidStr, nil
		}
	}

	if sub, ok := verifiedToken.Get("sub"); ok {
		if subStr, ok := sub.(string); ok {
			return subStr, nil
		}
	}

	return "", errors.New("no webid or sub claim in token")
}

// discoverJWKSURL discovers the JWKS URL from an OIDC issuer
func discoverJWKSURL(issuer string) (string, error) {
	// Try OIDC discovery
	discoveryURL := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"

	resp, err := http.Get(discoveryURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errors.New("OIDC discovery endpoint not found")
	}

	var discovery struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return "", err
	}

	if discovery.JWKSURI == "" {
		return "", errors.New("jwks_uri not found in discovery document")
	}

	return discovery.JWKSURI, nil
}

// validateTokenClaims validates the standard JWT claims
func validateTokenClaims(token jwt.Token, expectedIssuer string) error {
	// Check expiration
	if exp := token.Expiration(); !exp.IsZero() {
		if time.Now().After(exp) {
			return errors.New("token has expired")
		}
	}

	// Verify issuer matches
	if iss, ok := token.Get("iss"); ok {
		if issStr, ok := iss.(string); ok {
			if issStr != expectedIssuer {
				return errors.New("token issuer mismatch")
			}
		}
	}

	// Check not-before time
	if nbf := token.NotBefore(); !nbf.IsZero() {
		if time.Now().Before(nbf) {
			return errors.New("token not yet valid")
		}
	}

	return nil
}

// verifyTokenWithJWKS verifies a JWT token using the issuer's JWKS endpoint
func verifyTokenWithJWKS(tokenString string, jwksURL string) (jwt.Token, error) {
	keySet, err := jwk.Fetch(context.Background(), jwksURL)
	if err != nil {
		return nil, err
	}

	token, err := jwt.Parse([]byte(tokenString), jwt.WithKeySet(keySet))
	if err != nil {
		return nil, err
	}

	return token, nil
}
