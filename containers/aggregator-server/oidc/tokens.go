package oidc

import (
	"aggregator/model"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/sirupsen/logrus"
)

func FetchServiceAccountToken(ctx context.Context, tokenEndpoint string, clientID string, clientSecret string) (string, error) {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := model.HttpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("execute token request: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}

	return result.AccessToken, nil
}

func ValidateToken(tokenString string, issuer string, subject string, client string) (string, error) {
	logrus.WithField("token", tokenString).Debug("Starting token validation")

	// Parse token
	unverifiedToken, err := jwt.Parse([]byte(tokenString), jwt.WithValidate(false))
	if err != nil {
		logrus.WithError(err).Warn("Failed to parse IDP client token")
		return "", errors.New("invalid token format")
	}

	// Extract issuer
	iss, ok := unverifiedToken.Get("iss")
	if !ok {
		logrus.Warn("Token missing issuer claim")
		return "", errors.New("token missing issuer claim")
	}
	issStr, ok := iss.(string)
	if !ok {
		logrus.Warn("Invalid issuer claim format")
		return "", errors.New("invalid issuer claim")
	}
	logrus.Debugf("Token issuer: %s", issStr)

	// Discover JWKS URL
	jwksURL, err := discoverJWKSURL(issStr)
	if err != nil {
		logrus.WithError(err).Warnf("Failed to discover JWKS URL for issuer %s", issStr)
		return "", errors.New("failed to discover JWKS endpoint")
	}
	logrus.Debugf("Discovered JWKS URL: %s", jwksURL)

	// Verify token signature
	verifiedToken, err := verifyTokenWithJWKS(tokenString, jwksURL)
	if err != nil {
		logrus.WithError(err).Warn("Token signature verification failed")
		return "", errors.New("invalid token signature")
	}
	logrus.Debug("Token signature verified")

	// Validate standard claims
	if exp := verifiedToken.Expiration(); !exp.IsZero() && time.Now().After(exp) {
		logrus.Info("Token has expired")
		return "", errors.New("token has expired")
	}
	if nbf := verifiedToken.NotBefore(); !nbf.IsZero() && time.Now().Before(nbf) {
		logrus.Info("Token not yet valid")
		return "", errors.New("token not yet valid")
	}

	// Verify issuer
	if issuer != "" && issStr != issuer {
		logrus.Warnf("Token issuer mismatch: expected %s, got %s", issuer, issStr)
		return "", errors.New("token issuer mismatch")
	}

	// Verify azp claim
	azp, ok := verifiedToken.Get("azp")
	if !ok {
		logrus.Warn("Token missing azp claim")
		return "", errors.New("token missing azp claim")
	}
	azpStr, ok := azp.(string)
	if !ok || (client != "" && azpStr != client) {
		logrus.Warnf("Token azp mismatch: expected %s, got %v", client, azp)
		return "", errors.New("token not issued for this client")
	}

	// Verify sub claim exists
	sub, ok := verifiedToken.Get("sub")
	if !ok {
		logrus.Warn("Token missing sub claim")
		return "", errors.New("token missing sub claim")
	}
	subStr, ok := sub.(string)
	if !ok || (subject != "" && subStr != subject) {
		logrus.Warnf("Token sub mismatch: expected %s, got %v", subject, sub)
		return "", errors.New("token not issued for this subject")
	}

	logrus.Debugf("Token validation passed, user ID: %s", subStr)
	return subStr, nil
}

// discoverJWKSURL discovers the JWKS URL from an OIDC issuer
func discoverJWKSURL(issuer string) (string, error) {
	// Try OIDC discovery
	discoveryURL := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"

	resp, err := model.HttpClient.Get(discoveryURL)
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

// verifyTokenWithJWKS verifies a JWT token using the issuer's JWKS endpoint
func verifyTokenWithJWKS(tokenString string, jwksURL string) (jwt.Token, error) {
	keySet, err := jwk.Fetch(context.Background(), jwksURL, jwk.WithHTTPClient(model.HttpClient))
	if err != nil {
		return nil, err
	}

	token, err := jwt.Parse([]byte(tokenString), jwt.WithKeySet(keySet))
	if err != nil {
		return nil, err
	}

	return token, nil
}
