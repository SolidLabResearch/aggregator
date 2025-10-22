package auth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
	"io"
	"math/big"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
)

const AS_ISSUER = "http://localhost:4000/uma"

func AuthorizeRequest(response http.ResponseWriter, request *http.Request, extraPermissions []Permission) bool {
	if request.Header.Get("Authorization") == "" {
		logrus.WithFields(logrus.Fields{"method": request.Method, "path": request.URL.Path}).Warn("🔐 Authorization header missing")
		scheme := "http"
		if request.TLS != nil {
			scheme = "https"
		}
		completeURL := fmt.Sprintf("%s://%s%s", scheme, request.Host, request.URL.Path)
		logrus.WithFields(logrus.Fields{"url": completeURL}).Info("🎫 Creating ticket")

		ticketPermissions := make(map[string][]string)
		ticketPermissions[completeURL] = BuildPermissions(completeURL, request.Method).ResourceScopes
		if extraPermissions != nil {
			logrus.WithFields(logrus.Fields{"count": len(extraPermissions)}).Debug("➕ Adding extra permissions")
			for _, permission := range extraPermissions {
				ticketPermissions[permission.ResourceID] = permission.ResourceScopes
				logrus.WithFields(logrus.Fields{"resource_id": permission.ResourceID, "scopes": permission.ResourceScopes}).Debug("Extra permission")
			}
		}
		ticket, err := fetchTicket(ticketPermissions, AS_ISSUER)
		if err != nil {
			logrus.WithFields(logrus.Fields{"err": err}).Error("❌ Error while retrieving ticket")
			http.Error(response, "error while retrieving ticket", http.StatusUnauthorized)
			return false
		}
		if ticket == "" {
			logrus.Info("✅ No ticket needed - access granted immediately")
			return true
		}
		logrus.WithFields(logrus.Fields{"url": completeURL, "as_uri": AS_ISSUER}).Info("🎫 Ticket created successfully, sending WWW-Authenticate header")
		response.Header().Set(
			"WWW-Authenticate",
			fmt.Sprintf(`UMA as_uri="%s", ticket="%s"`, AS_ISSUER, ticket),
		)
		response.WriteHeader(http.StatusUnauthorized)
		return false
	}

	logrus.WithFields(logrus.Fields{"method": request.Method, "path": request.URL.Path}).Info("🔍 Verifying authorization token")
	permission, err := VerifyTicket(request.Header.Get("Authorization"), []string{"http://localhost:4000/uma"})
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("❌ Error while verifying ticket")
		response.WriteHeader(http.StatusBadRequest)
		return false
	}

	scheme := "http"
	if request.TLS != nil {
		scheme = "https"
	}
	completeURL := fmt.Sprintf("%s://%s%s", scheme, request.Host, request.URL.Path)
	logrus.WithFields(logrus.Fields{"url": completeURL}).Debug("🌐 Checking permissions for URL")

	resourceId, exists := idIndex[completeURL]
	if exists {
		logrus.WithFields(logrus.Fields{"url": completeURL, "resource_id": resourceId}).Debug("📋 Found resource ID")
	} else {
		logrus.WithFields(logrus.Fields{"url": completeURL}).Warn("⚠️ No resource ID found in idIndex")
		return false
	}

	logrus.WithFields(logrus.Fields{"count": len(permission), "permissions": permission}).Debug("🔑 User permissions retrieved")
	if CheckPermission(completeURL, request.Method, permission) {
		return true
	}

	logrus.WithFields(logrus.Fields{"resource_id": idIndex[completeURL], "permissions": permission}).Warn("❌ No matching permission found")
	response.WriteHeader(http.StatusBadRequest)
	return false
}

type UmaConfig struct {
	jwksUri                      string
	issuer                       string
	permissionEndpoint           string
	introspectionEndpoint        string
	resourceRegistrationEndpoint string
}

type Permission struct {
	ResourceID     string   `json:"resource_id"`
	ResourceScopes []string `json:"resource_scopes"`
}

// UmaClaims extends the standard JWT claims with an optional "permissions" array.
type UmaClaims struct {
	jwt.RegisteredClaims
	Permissions []Permission `json:"permissions,omitempty"`
}

func fetchTicket(permissions map[string][]string, issuer string) (string, error) {
	config, err := fetchUmaConfig(issuer)
	if err != nil {
		return "", fmt.Errorf("error while retrieving config: %v", err)
	}

	var body []Permission
	for target, modes := range permissions {
		resourceScopes := make([]string, len(modes))
		for i, mode := range modes {
			resourceScopes[i] = mode
		}
		body = append(body, Permission{
			ResourceID:     target,
			ResourceScopes: resourceScopes,
		})
	}

	jsonData, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", config.permissionEndpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := doSignedRequest(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	logrus.WithFields(logrus.Fields{"status_code": resp.StatusCode}).Debug("Permission endpoint response status")

	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
		logrus.WithFields(logrus.Fields{"body": string(bodyBytes)}).Debug("Permission endpoint response body")
		return "", nil
	}

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
		bodyString := string(bodyBytes)
		return "", fmt.Errorf(
			"error while retrieving UMA Ticket: Received status %d with message \"%s\" from '%s'",
			resp.StatusCode,
			bodyString,
			config.permissionEndpoint,
		)
	}

	var jsonResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&jsonResponse); err != nil {
		return "", err
	}

	ticket, ok := jsonResponse["ticket"].(string)
	if !ok || ticket == "" {
		return "", errors.New("invalid response from UMA AS: missing or invalid 'ticket'")
	}

	return ticket, nil
}

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

// IntrospectionResponse models the OAuth2/UMA token introspection output we rely on
// See RFC 7662: at minimum we use 'active' and optional 'exp' (as UNIX seconds)
// Other fields are ignored for now.
type IntrospectionResponse struct {
	Active   bool   `json:"active"`
	Exp      int64  `json:"exp,omitempty"`
	Scope    string `json:"scope,omitempty"`
	ClientID string `json:"client_id,omitempty"`
	Sub      string `json:"sub,omitempty"`
	Iss      string `json:"iss,omitempty"`
}

// IntrospectToken performs UMA/OAuth2 token introspection against the configured issuer.
// It returns the parsed IntrospectionResponse. If the token is not active, Active will be false.
func IntrospectToken(token, issuer string) (IntrospectionResponse, error) {
	config, err := fetchUmaConfig(issuer)
	if err != nil {
		return IntrospectionResponse{}, fmt.Errorf("error fetching UMA config: %w", err)
	}

	payload := map[string]string{"token": token}
	body, err := json.Marshal(payload)
	if err != nil {
		return IntrospectionResponse{}, fmt.Errorf("failed to marshal introspection body: %w", err)
	}

	req, err := http.NewRequest("POST", config.introspectionEndpoint, bytes.NewBuffer(body))
	if err != nil {
		return IntrospectionResponse{}, fmt.Errorf("failed to create introspection request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := doSignedRequest(req)
	if err != nil {
		return IntrospectionResponse{}, fmt.Errorf("introspection request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return IntrospectionResponse{}, fmt.Errorf("introspection endpoint returned status %d: %s", resp.StatusCode, string(b))
	}

	var ir IntrospectionResponse
	if err := json.NewDecoder(resp.Body).Decode(&ir); err != nil {
		return IntrospectionResponse{}, fmt.Errorf("failed to decode introspection response: %w", err)
	}

	logrus.WithFields(logrus.Fields{"active": ir.Active, "exp": ir.Exp}).Debug("UMA token introspected")
	return ir, nil
}

// Introspect is a convenience wrapper using the default AS_ISSUER.
func Introspect(token string) (IntrospectionResponse, error) {
	return IntrospectToken(token, AS_ISSUER)
}

func verifyTicket(token string, validIssuers []string) ([]Permission, error) {
	// Remove 'Bearer ' prefix if present (case-insensitive)
	token = strings.TrimSpace(token)
	if len(token) > 7 && strings.ToLower(token[:7]) == "bearer " {
		token = strings.TrimSpace(token[7:])
	}

	payloadMap, err := decodeJwtPayload(token)
	if err != nil {
		return nil, fmt.Errorf("error decoding JWT: %w", err)
	}

	issVal, ok := payloadMap["iss"].(string)
	if !ok || issVal == "" {
		return nil, errors.New(`the JWT does not contain an "iss" parameter`)
	}

	hasValidIssuer := false
	for _, issuer := range validIssuers {
		if issuer == issVal {
			hasValidIssuer = true
		}
	}
	if !hasValidIssuer {
		return nil, errors.New(`the JWT wasn't issued by one of the target owners' issuers`)
	}

	config, err := fetchUmaConfig(issVal)
	if err != nil {
		return nil, fmt.Errorf("error fetching UMA config: %w", err)
	}

	// Parse and validate with our chosen public key.
	// We'll also check the issuer in the claims.
	claims := &UmaClaims{}
	parser := jwt.NewParser()
	parsedToken, err := parser.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		return fetchAndSelectKey(config.jwksUri, "TODO")

		// Auth server doesn't have kid's so we just return the first key
		/*
			// We'll look at t.Header["kid"] to figure out which key to use
			kidVal, hasKid := t.Header["kid"]
			if !hasKid {
				return nil, errors.New("token header missing 'kid'")
			}
			kid, ok := kidVal.(string)
			if !ok {
				return nil, fmt.Errorf("'kid' in header is not a string: %v", kidVal)
			}

			// Now fetch the JWKS from config.JwksUri and pick the correct public key.
			pubKey, err := fetchAndSelectKey(config.jwksUri, kid)
			if err != nil {
				return nil, fmt.Errorf("fetchAndSelectKey error: %w", err)
			}
			return pubKey, nil
		*/
	})

	if err != nil {
		return nil, err
	}

	if !parsedToken.Valid {
		return nil, errors.New("invalid token signature or claims")
	}

	if claims.Issuer != issVal {
		return nil, fmt.Errorf(`token "iss" (%s) does not match expected issuer (%s)`, claims.Issuer, issVal)
	}

	if claims.VerifyAudience("[solid]", true) {
		return nil, fmt.Errorf(`token "aud" (%s) does not match expected audience ("solid")`, claims.Audience)
	}

	// Check the permissions in the token
	if len(claims.Permissions) > 0 {
		for _, perm := range claims.Permissions {
			// resource_id must be a non-empty string
			if perm.ResourceID == "" {
				return nil, errors.New("Invalid RPT: 'permissions[].resource_id' missing or not a string")
			}
			// resource_scopes must be an array of strings
			if len(perm.ResourceScopes) == 0 {
				return nil, errors.New("Invalid RPT: 'permissions[].resource_scopes' missing or empty")
			}
			// Optionally check each scope is non-empty if needed
		}
	}

	// If we get here, the token is valid, and (if present) 'permissions' is well-formed.
	return claims.Permissions, nil
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

func FetchTicketForPermissions(permissions map[string][]string) (string, error) {
	return fetchTicket(permissions, AS_ISSUER)
}

func VerifyTicket(token string, validIssuers []string) ([]Permission, error) {
	if len(validIssuers) == 0 {
		validIssuers = []string{AS_ISSUER}
	}
	return verifyTicket(token, validIssuers)
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

	curve := elliptic.P256() // Default to P-256 curve
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

var REQUIRED_METADATA = []string{
	"issuer",
	"jwks_uri",
	"permission_endpoint",
	"introspection_endpoint",
	"resource_registration_endpoint",
}

func fetchUmaConfig(issuer string) (UmaConfig, error) {
	resp, err := http.Get(issuer + "/.well-known/uma2-configuration")
	if err != nil {
		return UmaConfig{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return UmaConfig{}, fmt.Errorf(
			"unable to retrieve UMA Configuration for Authorization Server '%s' from '%s'",
			issuer,
			issuer+"/.well-known/uma2-configuration",
		)
	}

	var configuration map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&configuration); err != nil {
		return UmaConfig{}, err
	}

	var umaConfig UmaConfig
	for _, value := range REQUIRED_METADATA {
		val, ok := configuration[value]
		if !ok {
			return UmaConfig{}, fmt.Errorf(
				"the Authorization Server Metadata of '%s' is missing attributes %s",
				issuer,
				value,
			)
		}
		strVal, ok := val.(string)
		if !ok {
			return UmaConfig{}, fmt.Errorf(
				"the Authorization Server Metadata of '%s' should have string attributes %s",
				issuer,
				value,
			)
		} else {
			switch value {
			case "issuer":
				umaConfig.issuer = strVal
			case "jwks_uri":
				umaConfig.jwksUri = strVal
			case "permission_endpoint":
				umaConfig.permissionEndpoint = strVal
			case "introspection_endpoint":
				umaConfig.introspectionEndpoint = strVal
			case "resource_registration_endpoint":
				umaConfig.resourceRegistrationEndpoint = strVal
			}
		}
	}

	return umaConfig, nil
}

var idIndex = make(map[string]string)

// ResourceScope enum-like type for UMA resource scopes
type ResourceScope string

const (
	ScopeRead             ResourceScope = "urn:example:css:modes:read"
	ScopeAppend           ResourceScope = "urn:example:css:modes:append"
	ScopeCreate           ResourceScope = "urn:example:css:modes:create"
	ScopeDelete           ResourceScope = "urn:example:css:modes:delete"
	ScopeWrite            ResourceScope = "urn:example:css:modes:write"
	ScopeContinuousRead   ResourceScope = "urn:example:css:modes:continuous:read"
	ScopeContinuousWrite  ResourceScope = "urn:example:css:modes:continuous:write"
	ScopeContinuousDuplex ResourceScope = "urn:example:css:modes:continuous:duplex"
)

func CreateResource(resourceId string, resourceScopes []ResourceScope) error {
	config, err := fetchUmaConfig(AS_ISSUER)
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("Error while retrieving UMA configuration")
		return err
	}

	knownUmaId := idIndex[resourceId]
	endpoint := config.resourceRegistrationEndpoint
	method := "POST"
	if knownUmaId != "" {
		endpoint = endpoint + "/" + knownUmaId
		method = "PUT"
	}

	// Generate resource description with name and resource_scopes
	scopeStrings := make([]string, len(resourceScopes))
	for i, scope := range resourceScopes {
		scopeStrings[i] = string(scope)
	}

	description := map[string]interface{}{
		"name":            resourceId,
		"resource_scopes": scopeStrings,
	}

	jsonData, err := json.Marshal(description)
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err, "resource_id": resourceId}).Error("Error while marshaling resource description")
		return err
	}

	req, err := http.NewRequest(method, endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err, "resource_id": resourceId}).Error("Error while creating UMA request")
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	action := "Creating"
	if knownUmaId != "" {
		action = "Updating"
	}
	logrus.WithFields(logrus.Fields{"action": action, "resource_id": resourceId, "endpoint": endpoint}).Info("Processing UMA resource registration")

	res, err := doSignedRequest(req)
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err, "resource_id": resourceId, "endpoint": endpoint}).Error("Error while making UMA request")
		return err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err, "status": res.Status, "resource_id": resourceId}).Error("Error while reading UMA response body")
		return err
	}

	if knownUmaId != "" {
		if res.StatusCode != http.StatusOK {
			logrus.WithFields(logrus.Fields{"status": res.Status, "body": string(body), "resource_id": resourceId}).Error("Resource update request failed")
			return nil
		}
	} else {
		if res.StatusCode != http.StatusCreated {
			logrus.WithFields(logrus.Fields{"status": res.Status, "body": string(body), "resource_id": resourceId}).Error("Resource registration request failed")
			return nil
		}
		var responseData struct {
			ID string `json:"_id"`
		}
		if err := json.Unmarshal(body, &responseData); err != nil {
			logrus.WithFields(logrus.Fields{"err": err, "resource_id": resourceId}).Error("Error while parsing UMA response JSON")
			return err
		}
		if responseData.ID == "" {
			logrus.WithFields(logrus.Fields{"resource_id": resourceId}).Warn("Unexpected UMA response; no UMA id received")
			return nil
		}
		idIndex[resourceId] = responseData.ID
		logrus.WithFields(logrus.Fields{"resource_id": resourceId, "uma_id": responseData.ID}).Info("Registered resource with UMA")
	}
	return nil
}

func DeleteResource(resourceId string) {
	config, err := fetchUmaConfig(AS_ISSUER)
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("Error while retrieving UMA configuration")
		return
	}

	authId := idIndex[resourceId]
	if authId == "" {
		logrus.WithFields(logrus.Fields{"resource_id": resourceId}).Warn("Resource not found in local index")
		return
	}

	req, err := http.NewRequest(
		"DELETE",
		config.resourceRegistrationEndpoint+"/"+authId,
		nil,
	)
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err, "resource_id": resourceId, "uma_id": authId}).Error("Error while creating UMA delete request")
		return
	}

	res, err := doSignedRequest(req)
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err, "resource_id": resourceId, "uma_id": authId}).Error("Error while making UMA delete request")
		return
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)

	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err, "status": res.Status, "resource_id": resourceId}).Error("Error while reading UMA delete response")
		return
	}
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusNoContent {
		logrus.WithFields(logrus.Fields{"status": res.Status, "body": string(body), "resource_id": resourceId, "uma_id": authId}).Error("Error while deleting UMA resource")
		logrus.WithFields(logrus.Fields{"trace": string(debug.Stack())}).Debug("Stack trace")
		return
	}

	logrus.WithFields(logrus.Fields{"resource_id": resourceId, "uma_id": authId}).Info("Resource deleted successfully")
	delete(idIndex, resourceId)
}

func DeleteAllResources() {
	config, err := fetchUmaConfig(AS_ISSUER)
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("Error while retrieving UMA configuration")
		return
	}
	for resourceId, authId := range idIndex {
		if authId == "" {
			logrus.WithFields(logrus.Fields{"resource_id": resourceId}).Warn("Resource not found in local index")
			return
		}

		req, err := http.NewRequest(
			"DELETE",
			config.resourceRegistrationEndpoint+authId,
			&bytes.Buffer{},
		)
		if err != nil {
			logrus.WithFields(logrus.Fields{"err": err, "resource_id": resourceId, "uma_id": authId}).Error("Error while creating UMA delete request")
			return
		}

		res, err := doSignedRequest(req)
		if err != nil {
			logrus.WithFields(logrus.Fields{"err": err, "resource_id": resourceId, "uma_id": authId}).Error("Error while making UMA delete request")
			return
		}
		defer res.Body.Close()
		body, err := io.ReadAll(res.Body)

		if err != nil {
			logrus.WithFields(logrus.Fields{"err": err, "status": res.Status}).Error("Error while reading UMA delete response")
			return
		}
		if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusNoContent {
			logrus.WithFields(logrus.Fields{"status": res.Status, "body": string(body), "resource_id": resourceId, "uma_id": authId}).Error("Error while deleting UMA resource")
			logrus.WithFields(logrus.Fields{"trace": string(debug.Stack())}).Debug("Stack trace")
			return
		}

		logrus.WithFields(logrus.Fields{"resource_id": resourceId, "uma_id": authId}).Info("Resource deleted successfully")
	}
	idIndex = make(map[string]string)
}

var (
	streamingResourcesMu sync.RWMutex
	streamingResources   = make(map[string]*StreamingResource)
)

// StreamingResource represents a resource that supports streaming and its required scope
type StreamingResource struct {
	URL   string
	Scope ResourceScope
}

// AddStreamingResource registers a streaming resource URL with its scope
func AddStreamingResource(url string, scope ResourceScope) {
	streamingResourcesMu.Lock()
	defer streamingResourcesMu.Unlock()
	streamingResources[url] = &StreamingResource{URL: url, Scope: scope}
}

// IsStreamingResource checks if a URL is configured as a streaming resource
func IsStreamingResource(url string) (*StreamingResource, bool) {
	streamingResourcesMu.RLock()
	defer streamingResourcesMu.RUnlock()
	res, ok := streamingResources[url]
	return res, ok
}

// BuildPermissions determines the UMA permissions for a given resource URL and HTTP method.
func BuildPermissions(resourceURL, method string) Permission {
	if res, ok := IsStreamingResource(resourceURL); ok {
		logrus.WithFields(logrus.Fields{"resource_id": resourceURL, "scopes": res.Scope}).Debug("Build permissions")
		return Permission{
			ResourceID:     resourceURL,
			ResourceScopes: []string{string(res.Scope)},
		}
	}

	var scopes []string
	switch method {
	case http.MethodGet, http.MethodHead:
		scopes = []string{string(ScopeRead)}
	case http.MethodPost:
		scopes = []string{string(ScopeCreate)}
	case http.MethodPut, http.MethodPatch:
		scopes = []string{string(ScopeWrite)}
	case http.MethodDelete:
		scopes = []string{string(ScopeDelete)}
	default:
		logrus.WithFields(logrus.Fields{"method": method, "resource_url": resourceURL}).Warn("Unsupported method")
		scopes = []string{string(ScopeWrite)}
	}

	logrus.WithFields(logrus.Fields{"resource_id": resourceURL, "scopes": scopes[0]}).Debug("Build permissions")
	return Permission{
		ResourceID:     resourceURL,
		ResourceScopes: scopes,
	}
}

// CheckPermission determines the UMA permissions for a given resource URL and HTTP method.
func CheckPermission(resourceURL, method string, permission []Permission) bool {
	if res, ok := IsStreamingResource(resourceURL); ok {
		for _, perm := range permission {
			if perm.ResourceID == resourceURL {
				if contains(perm.ResourceScopes, string(res.Scope)) {
					logrus.Info("✅ Authorization successful - user has streaming permissions")
					return true
				}
				logrus.WithFields(logrus.Fields{"user_scopes": perm.ResourceScopes}).Warn("❌ Authorization failed - missing streaming scope")
				return false
			}
		}
	}

	for _, perm := range permission {
		if perm.ResourceID == idIndex[resourceURL] {
			logrus.WithFields(logrus.Fields{"resource_id": perm.ResourceID}).Debug("✅ Found matching permission")
			switch method {
			case http.MethodGet, http.MethodHead:
				logrus.WithFields(logrus.Fields{"method": method}).Debug("📖 Checking for 'read' scope")
				if contains(perm.ResourceScopes, string(ScopeRead)) {
					logrus.Info("✅ Authorization successful - user has read permissions")
					return true
				}
				break
			case http.MethodPost:
				logrus.WithFields(logrus.Fields{"method": method}).Debug("🔧 Checking for 'create' scope")
				if contains(perm.ResourceScopes, string(ScopeCreate)) {
					logrus.Info("✅ Authorization successful - user has modify permissions")
					return true
				}
				break
			case http.MethodPatch, http.MethodPut:
				logrus.WithFields(logrus.Fields{"method": method}).Debug("🔧 Checking for 'write' scope")
				if contains(perm.ResourceScopes, string(ScopeWrite)) {
					logrus.Info("✅ Authorization successful - user has modify permissions")
					return true
				}
				break
			case http.MethodDelete:
				logrus.WithFields(logrus.Fields{"method": method}).Debug("🔧 Checking for 'delete' scope")
				if contains(perm.ResourceScopes, string(ScopeDelete)) {
					logrus.Info("✅ Authorization successful - user has modify permissions")
					return true
				}
				break
			}
			logrus.WithFields(logrus.Fields{"resource_id": perm.ResourceID, "method": method, "user_scopes": perm.ResourceScopes}).Warn("❌ Authorization failed - missing modify scope")
			return false
		}
	}
	logrus.WithFields(logrus.Fields{"resource_id": resourceURL, "method": method}).Warn("❌ Authorization failed - no matching resource ID & scope found in permissions")
	return false
}
