package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
)

type JWK struct {
	Kty string      `json:"kty"`
	Kid string      `json:"kid"`
	Alg string      `json:"alg,omitempty"`
	Use string      `json:"use,omitempty"`
	N   string      `json:"n,omitempty"` // Modulus
	E   string      `json:"e,omitempty"` // Exponent
	X   string      `json:"x,omitempty"`
	Y   string      `json:"y,omitempty"`
	Crv interface{} `json:"crv,omitempty"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func fetchAndSelectKey(jwksUri, kid string) (interface{}, error) {
	// 1) Fetch the JWKS JSON
	resp, err := http.Get(jwksUri)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS from %s: %w", jwksUri, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS body: %w", err)
	}

	var jwks JWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWKS: %w", err)
	}

	if len(jwks.Keys) == 0 {
		return nil, errors.New("no keys found in JWKS")
	}

	return parsePublicKeyFromJWK(jwks.Keys[0])

	// the authentication server currently doesn't support kid's so we just return the first key
	/*

		// 3) Find the key with matching kid
		for _, jwk := range jwks.Keys {
			if jwk.Kid == kid {
				// We found the correct JWK. Let's parse it as an RSA key.
				return parseRSAPublicKeyFromJWK(jwk)
			}
		}

		return nil, fmt.Errorf("no matching key found for kid=%s in JWKS", kid)
	*/
}

func parsePublicKeyFromJWK(jwk JWK) (interface{}, error) {
	switch jwk.Kty {
	case "RSA":
		return parseRSAPublicKeyFromJWK(jwk)
	case "EC":
		return parseECPublicKeyFromJWK(jwk)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}
}

func parseRSAPublicKeyFromJWK(jwk JWK) (*rsa.PublicKey, error) {
	if jwk.Kty != "RSA" {
		return nil, fmt.Errorf("expected RSA kty but got %s", jwk.Kty)
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode 'n' in JWK: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode 'e' in JWK: %w", err)
	}

	// Convert eBytes to int
	var eInt int
	for _, b := range eBytes {
		eInt = eInt<<8 | int(b)
	}

	pubKey := &rsa.PublicKey{
		N: bytesToBigInt(nBytes),
		E: eInt,
	}
	return pubKey, nil
}

func parseECPublicKeyFromJWK(jwk JWK) (*ecdsa.PublicKey, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode 'x' in JWK: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode 'y' in JWK: %w", err)
	}

	var curve elliptic.Curve
	switch jwk.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", jwk.Crv)
	}

	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     bytesToBigInt(xBytes),
		Y:     bytesToBigInt(yBytes),
	}
	return pubKey, nil
}

func bytesToBigInt(b []byte) *big.Int {
	bi := new(big.Int)
	bi.SetBytes(b)
	return bi
}

func decodeJwtPayload(tokenString string) (map[string]interface{}, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) < 2 {
		return nil, errors.New("invalid JWT format (missing segments)")
	}
	// The second part is the payload
	payloadSegment := parts[1]

	decoded, err := base64.RawURLEncoding.DecodeString(payloadSegment)
	if err != nil {
		// Some libraries use regular base64 with or without padding; you might need to handle that
		return nil, fmt.Errorf("failed to base64-decode JWT payload: %w", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(decoded, &payload); err != nil {
		return nil, fmt.Errorf("failed to JSON-decode JWT payload: %w", err)
	}
	return payload, nil
}
