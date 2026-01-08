package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"ingress-uma/signing"
	"io"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
)

type Permission struct {
	UmaId          string  `json:"resource_id"`
	ResourceScopes []Scope `json:"resource_scopes"`
}

type UmaClaims struct {
	jwt.RegisteredClaims
	Permissions []Permission `json:"permissions,omitempty"`
}

var ExternalHost string
var DisableAuth bool

func InitAuth(extHost string, disbaleAuth bool) {
	ExternalHost = extHost
	DisableAuth = disbaleAuth
}

func HandleAuthorizationRequest(w http.ResponseWriter, r *http.Request) {
	// Extract the UMA information from the forwarded headers
	scheme := strings.Trim(r.Header.Get("X-Forwarded-Proto"), "[]")
	resourcePath := strings.Trim(r.Header.Get("X-Forwarded-Uri"), "[]")
	resourceId := fmt.Sprintf("%s://%s%s", scheme, ExternalHost, resourcePath)
	umaId := idIndex[resourceId]
	if umaId == "" {
		logrus.WithFields(logrus.Fields{"resource": resourceId}).Warn("No UMA id found for resource")
		http.Error(w, "No UMA id found for resource", http.StatusUnauthorized)
		return
	}

	issuer := issuerIndex[resourceId]
	if issuer == "" {
		logrus.Warn("No Authentication Server Url found for resource")
		http.Error(w, "No Authentication Server Url found for resource", http.StatusUnauthorized)
		return
	}

	method := forwardedMethod(r)
	logrus.WithFields(logrus.Fields{
		"resource": resourceId,
		"uma_id":   umaId,
		"method":   method,
		"as_url":   issuer,
	}).Info("Authorize request")

	// Always authorize if disabled for testing
	if DisableAuth {
		logrus.Info("✅ Authentication disabled - access granted immediately")
		w.WriteHeader(http.StatusOK)
		return
	}

	// No ticket
	if r.Header.Get("Authorization") == "" {
		ticketlessAuthorization(w, r, umaId, issuer)
		return
	}

	// With ticket
	ticketedAuthorization(w, r, umaId, issuer)
}

func ticketlessAuthorization(w http.ResponseWriter, r *http.Request, umaId string, issuer string) {
	method := forwardedMethod(r)
	permissions := make(map[string][]Scope)
	scopes, err := determineScopes(method)
	if err != nil {
		logrus.WithError(err).Error("Error determining scopes")
		http.Error(w, "Error determining scopes", http.StatusUnauthorized)
		return
	}
	permissions[umaId] = scopes

	ticket, err := fetchTicket(issuer, permissions)
	if err != nil {
		logrus.WithError(err).Error("Error while fetching ticket")
		http.Error(w, "Error while fetching ticket", http.StatusUnauthorized)
		return
	}

	// no ticket needed
	if ticket == "" {
		logrus.Info("✅ No ticket needed - access granted immediately")
		w.WriteHeader(http.StatusOK)
		return
	}

	// return ticket with WWW-Authenticate header
	logrus.Info("🎫 Ticket created successfully, sending WWW-Authenticate header")
	w.Header().Set(
		"WWW-Authenticate",
		fmt.Sprintf(`UMA as_uri="%s", ticket="%s"`, issuer, ticket),
	)
	w.WriteHeader(http.StatusUnauthorized)
}

func ticketedAuthorization(w http.ResponseWriter, r *http.Request, umaId string, issuer string) {
	method := forwardedMethod(r)
	logrus.WithFields(logrus.Fields{"method": method, "path": r.URL.Path}).Info("🔍 Verifying authorization token")
	permission, err := verifyTicket(r.Header.Get("Authorization"), []string{issuer})
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("❌ Error while verifying ticket")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	logrus.WithFields(logrus.Fields{"count": len(permission), "permissions": permission}).Debug("🔑 User permissions retrieved")

	// Determine required scopes for this request
	requiredScopes, err := determineScopes(method)
	if err != nil {
		logrus.WithError(err).Error("Error determining scopes")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Check permissions
	for _, perm := range permission {
		// Find matching permission for this resource
		if perm.UmaId == umaId {
			logrus.WithFields(logrus.Fields{"resource_id": perm.UmaId}).Debug("✅ Found matching permission")
			// Check if required scopes are satisfied
			if checkScopes(perm.ResourceScopes, requiredScopes) {
				logrus.Info("✅ Required scopes are satisfied - access granted")
				w.WriteHeader(http.StatusOK)
				return
			} else {
				logrus.WithFields(logrus.Fields{"required_scopes": requiredScopes, "permissioned_scopes": perm.ResourceScopes}).Warn("❌ Required scopes are NOT satisfied")
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}
	}

	// No matching permission for the resource was found
	logrus.WithFields(logrus.Fields{"resource_id": umaId, "permissions": permission}).Warn("❌ No matching permission found")
	w.WriteHeader(http.StatusBadRequest)
}

func fetchTicket(asUrl string, permissions map[string][]Scope) (string, error) {
	config, err := fetchUmaConfig(asUrl)
	if err != nil {
		return "", fmt.Errorf("error while retrieving config: %w", err)
	}

	// Create body with permissions
	body := []Permission{}
	for id, scopes := range permissions {
		body = append(body, Permission{
			UmaId:          id,
			ResourceScopes: scopes,
		})
	}

	jsonData, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("error while constructing body: %w", err)
	}

	// Request ticket
	req, err := http.NewRequest("POST", config.PermissionEndpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := signing.DoSignedRequest(req)
	if err != nil {
		return "", fmt.Errorf("error while signing ticket request: %w", err)
	}
	defer resp.Body.Close()
	logrus.WithFields(logrus.Fields{"status_code": resp.StatusCode}).Debug("Permission endpoint response status")

	// No ticket needed
	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("error while parsing response body with statuscode %d: %w", resp.StatusCode, err)
		}
		logrus.WithFields(logrus.Fields{"body": string(bodyBytes)}).Debug("Permission endpoint response body")
		return "", nil
	}

	// Failed to fetch ticket
	if resp.StatusCode != http.StatusCreated {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("error while parsing response body with statuscode %d: %w", resp.StatusCode, err)
		}
		bodyString := string(bodyBytes)
		return "", fmt.Errorf(
			"error while fetching ticket from %s: Status %d with message \"%s\"",
			config.PermissionEndpoint,
			resp.StatusCode,
			bodyString,
		)
	}

	var jsonResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&jsonResponse); err != nil {
		return "", err
	}

	// Return ticket
	ticket, ok := jsonResponse["ticket"].(string)
	if !ok || ticket == "" {
		return "", fmt.Errorf("invalid response from persmission endpoint %s: No ticket in response", config.PermissionEndpoint)
	}

	return ticket, nil
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
		return fetchAndSelectKey(config.JwksUri, "TODO")

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
			if perm.UmaId == "" {
				return nil, errors.New("invalid RPT: 'permissions[].resource_id' missing or not a string")
			}
			// resource_scopes must be an array of strings
			if len(perm.ResourceScopes) == 0 {
				return nil, errors.New("invalid RPT: 'permissions[].resource_scopes' missing or empty")
			}
			// Optionally check each scope is non-empty if needed
		}
	}

	// If we get here, the token is valid, and (if present) 'permissions' is well-formed.
	return claims.Permissions, nil
}

func forwardedMethod(r *http.Request) string {
	method := strings.Trim(r.Header.Get("X-Forwarded-Method"), "[]")
	if method == "" {
		method = r.Method
	}
	return method
}
