package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/sirupsen/logrus"
)

var client = &http.Client{} // restored global HTTP client
var solidAuth *SolidAuth    // restored global SolidAuth instance

type claimToken struct {
	ClaimToken       string `json:"claim_token"`
	ClaimTokenFormat string `json:"claim_token_format"`
}

type permission struct {
	ResourceID     string   `json:"resource_id"`
	ResourceScopes []string `json:"resource_scopes"`
}

type requiredClaim struct {
	ClaimTokenFormat string `json:"claim_token_format"`
	Details          struct {
		Issuer         string   `json:"issuer"`
		ResourceID     string   `json:"resource_id"`
		ResourceScopes []string `json:"resource_scopes"`
	} `json:"details"`
}

// fetchAccessToken performs UMA token acquisition with recursive claim gathering on 403.
// Returns access token, token type, optional derivation resource id, and expires_in.
func fetchAccessToken(tokenEndpoint string, request interface{}, claims []claimToken) (string, string, string, int, error) {
	// Initialize with single ID token claim if none provided.
	if claims == nil || len(claims) == 0 {
		idTok, err := solidAuth.CreateClaimToken()
		if err != nil {
			return "", "", "", 0, fmt.Errorf("failed to create initial claim token: %w", err)
		}
		claims = []claimToken{{
			ClaimToken:       idTok,
			ClaimTokenFormat: "http://openid.net/specs/openid-connect-core-1_0.html#IDToken",
		}}
	}

	body := map[string]any{
		"grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
		"scope":      "urn:knows:uma:scopes:derivation-creation",
	}

	// Single vs multi claim representation to mimic reference implementation.
	if len(claims) == 1 {
		body["claim_token"] = claims[0].ClaimToken
		body["claim_token_format"] = claims[0].ClaimTokenFormat
	} else {
		body["claim_tokens"] = claims
	}

	switch v := request.(type) {
	case string: // ticket
		body["ticket"] = v
	case []permission:
		body["permissions"] = v
	default:
		return "", "", "", 0, fmt.Errorf("unsupported request type for fetchAccessToken: %T", request)
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return "", "", "", 0, err
	}

	tokenReq, err := createRequestWithRedirect("POST", tokenEndpoint, bytes.NewReader(payload))
	if err != nil {
		return "", "", "", 0, err
	}
	tokenReq.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(tokenReq)
	if err != nil {
		return "", "", "", 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	logrus.WithFields(logrus.Fields{"status_code": resp.StatusCode, "endpoint": tokenEndpoint}).Debug("UMA token endpoint response")

	// 403 -> gather required claims then recurse.
	if resp.StatusCode == http.StatusForbidden {
		var forbidden struct {
			Ticket         string          `json:"ticket"`
			RequiredClaims []requiredClaim `json:"required_claims"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&forbidden); err != nil {
			return "", "", "", 0, fmt.Errorf("failed to decode forbidden response: %w", err)
		}
		updatedClaims, err := gatherClaims(claims, forbidden.RequiredClaims)
		if err != nil {
			return "", "", "", 0, err
		}
		return fetchAccessToken(tokenEndpoint, forbidden.Ticket, updatedClaims)
	}

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", "", "", 0, fmt.Errorf("failed to fetch access token: status %d body %s", resp.StatusCode, string(b))
	}

	var okResp struct {
		AccessToken          string `json:"access_token"`
		TokenType            string `json:"token_type"`
		DerivationResourceID string `json:"derivation_resource_id"`
		ExpiresIn            int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&okResp); err != nil {
		return "", "", "", 0, fmt.Errorf("failed to decode token response: %w", err)
	}

	if okResp.AccessToken == "" || okResp.TokenType == "" {
		return "", "", "", 0, fmt.Errorf("incomplete token response")
	}
	return okResp.AccessToken, okResp.TokenType, okResp.DerivationResourceID, okResp.ExpiresIn, nil
}

// gatherClaims augments the claims slice based on server-required claims.
func gatherClaims(existing []claimToken, required []requiredClaim) ([]claimToken, error) {
	claims := existing
	for _, rc := range required {
		switch rc.ClaimTokenFormat {
		case "http://openid.net/specs/openid-connect-core-1_0.html#IDToken":
			idTok, err := solidAuth.CreateClaimToken()
			if err != nil {
				return nil, err
			}
			claims = append(claims, claimToken{ClaimToken: idTok, ClaimTokenFormat: rc.ClaimTokenFormat})
		case "urn:ietf:params:oauth:token-type:access_token":
			// Obtain nested access token using permissions.
			perm := []permission{{ResourceID: rc.Details.ResourceID, ResourceScopes: rc.Details.ResourceScopes}}
			at, _, _, _, err := fetchAccessToken(rc.Details.Issuer+"/token", perm, nil)
			if err != nil {
				return nil, err
			}
			claims = append(claims, claimToken{ClaimToken: at, ClaimTokenFormat: rc.ClaimTokenFormat})
		default:
			return nil, fmt.Errorf("unsupported claim token format: %s", rc.ClaimTokenFormat)
		}
	}
	return claims, nil
}

func Do(req *http.Request) (*http.Response, error) {
	// Redirect localhost URLs to host machine
	originalURL := req.URL.String()
	originalHost := req.Host
	if originalHost == "" {
		originalHost = req.URL.Host
	}

	redirectedURL := redirectLocalhostURL(originalURL)
	if redirectedURL != originalURL {
		newURL, err := url.Parse(redirectedURL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse redirected URL: %v", err)
		}
		req.URL = newURL

		// If we redirected a localhost URL, preserve the original Host header
		if strings.HasPrefix(originalHost, "localhost") || strings.HasPrefix(originalHost, "127.0.0.1") {
			req.Host = originalHost
			logrus.WithFields(logrus.Fields{"original_host": originalHost}).Debug("🔧 Setting Host header to original value")
		}
	}

	// If no authentication is configured, just pass through the request
	if solidAuth == nil {
		return client.Do(req)
	}
	// Attempt to use cached UMA token first
	method := req.Method
	resourceURL := req.URL.String()
	if tokenType, accessToken, ok := solidAuth.getUmaToken(method, resourceURL); ok {
		logrus.WithFields(logrus.Fields{"url": resourceURL}).Debug("Using cached UMA token")
		req.Header.Set("Authorization", fmt.Sprintf("%s %s", tokenType, accessToken))
		cachedResp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		if cachedResp.StatusCode != http.StatusUnauthorized {
			return cachedResp, nil
		}
		// Cached token failed; remove and proceed unauthenticated.
		solidAuth.deleteUmaToken(method, resourceURL)
		logrus.WithFields(logrus.Fields{"url": resourceURL}).Info("Cached UMA token unauthorized, retrying without token")
	}
	// Clear any Authorization header set by failed cached attempt
	if req.Header.Get("Authorization") != "" {
		req.Header.Del("Authorization")
	}
	// Perform unauthenticated request
	unauthenticatedResp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if unauthenticatedResp.StatusCode == http.StatusUnauthorized {
		defer func() { _ = unauthenticatedResp.Body.Close() }()
		asUri, ticket, err := getTicketInfo(unauthenticatedResp.Header.Get("WWW-Authenticate"))
		if err != nil {
			return nil, err
		}

		logrus.WithFields(logrus.Fields{"asUri": asUri}).Info("Received UMA ticket")
		reqConf, err := createRequestWithRedirect("GET", asUri+"/.well-known/uma2-configuration", nil)
		if err != nil {
			return nil, err
		}
		uma2ConfigResponse, err := client.Do(reqConf)
		if err != nil {
			return nil, fmt.Errorf("failed to get UMA2 configuration: %w", err)
		}
		defer func() { _ = uma2ConfigResponse.Body.Close() }()

		if uma2ConfigResponse.StatusCode != http.StatusOK {
			return unauthenticatedResp, nil
		}

		var uma2Config struct {
			TokenEndpoint string `json:"token_endpoint"`
		}
		if err := json.NewDecoder(uma2ConfigResponse.Body).Decode(&uma2Config); err != nil {
			return nil, fmt.Errorf("failed to decode UMA2 config: %w", err)
		}

		tokenEndpoint := uma2Config.TokenEndpoint

		accessToken, tokenType, derivationResourceId, expiresIn, err := fetchAccessToken(tokenEndpoint, ticket, nil)
		if err != nil {
			return nil, err
		}
		// Store in cache before retry
		solidAuth.storeUmaToken(method, resourceURL, tokenType, accessToken, expiresIn)
		req.Header.Set("Authorization", fmt.Sprintf("%s %s", tokenType, accessToken))
		authorizedResp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		// Derivation headers may not be available now; skip if absent.
		if derivationResourceId != "" {
			authorizedResp.Header.Set("X-Derivation-Resource-Id", derivationResourceId)
			authorizedResp.Header.Set("X-Derivation-Issuer", asUri)
		}
		return authorizedResp, nil
	}
	// If the response is not unauthorized, return it as is
	logrus.Debug("No authorization needed")
	return unauthenticatedResp, nil
}

func getTicketInfo(headerString string) (string, string, error) {
	header := strings.TrimPrefix(headerString, "UMA ")
	params := strings.Split(header, ", ")
	var asUri string
	var ticket string
	for _, param := range params {
		keyValue := strings.Split(param, "=")
		if len(keyValue) != 2 {
			return "", "", fmt.Errorf("invalid parameter: %s", param)
		}
		key := strings.ReplaceAll(keyValue[0], "\"", "")
		value := strings.ReplaceAll(keyValue[1], "\"", "")
		switch key {
		case "as_uri":
			asUri = value
		case "ticket":
			ticket = value
		default:
			logrus.WithFields(logrus.Fields{"header string": headerString, "key": key, "value": value}).Debug("Unknown UMA parameter")
		}
	}
	return asUri, ticket, nil
}
