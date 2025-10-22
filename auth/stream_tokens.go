package auth

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"sync"
	"time"
)

var streamKeyMu sync.RWMutex

// StreamTokenClaims defines the JWT payload used for stream/session authorization.
type StreamTokenClaims struct {
	jwt.RegisteredClaims
	SessionID   string `json:"sid"`
	ResourceURL string `json:"res"`
	Scope       string `json:"scope"`
}

// GenerateStreamToken issues a signed JWT tied to a specific streaming session/resource.
// The issuer parameter should typically be the aggregator's external base URL so receivers
// can validate provenance.
func GenerateStreamToken(sessionID, resourceURL, issuer string, scope ResourceScope, ttl time.Duration) (string, time.Time, error) {
	if sessionID == "" {
		return "", time.Time{}, errors.New("sessionID is required")
	}
	if resourceURL == "" {
		return "", time.Time{}, errors.New("resourceURL is required")
	}
	if ttl <= 0 {
		return "", time.Time{}, errors.New("ttl must be positive")
	}

	streamKeyMu.RLock()
	key := rsaPrivateKey
	streamKeyMu.RUnlock()

	if key == nil {
		return "", time.Time{}, errors.New("signing key not initialised")
	}

	now := time.Now().UTC()
	expiresAt := now.Add(ttl)

	claims := StreamTokenClaims{
		SessionID:   sessionID,
		ResourceURL: resourceURL,
		Scope:       string(scope),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   sessionID,
			Audience:  jwt.ClaimStrings{resourceURL},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.NewString(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if keyID != "" {
		token.Header["kid"] = keyID
	}

	signed, err := token.SignedString(key)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign stream token: %w", err)
	}

	return signed, expiresAt, nil
}

// ParseStreamToken validates the JWT and returns its claims.
// expectedIssuer/resource may be empty to skip corresponding checks.
func ParseStreamToken(tokenString, expectedIssuer, expectedResource string) (*StreamTokenClaims, error) {
	if tokenString == "" {
		return nil, errors.New("token string is empty")
	}

	streamKeyMu.RLock()
	key := rsaPrivateKey
	streamKeyMu.RUnlock()

	if key == nil {
		return nil, errors.New("signing key not initialised")
	}

	parser := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))
	claims := &StreamTokenClaims{}

	parsed, err := parser.ParseWithClaims(tokenString, claims, func(_ *jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse stream token: %w", err)
	}
	if !parsed.Valid {
		return nil, errors.New("invalid stream token signature or claims")
	}
	if claims.SessionID == "" {
		return nil, errors.New("stream token missing session id")
	}
	if expectedIssuer != "" && claims.Issuer != expectedIssuer {
		return nil, fmt.Errorf("unexpected issuer %q", claims.Issuer)
	}
	if expectedResource != "" && claims.ResourceURL != expectedResource {
		return nil, fmt.Errorf("unexpected resource %q", claims.ResourceURL)
	}
	if claims.Scope == "" {
		return nil, errors.New("stream token missing scope")
	}

	return claims, nil
}
