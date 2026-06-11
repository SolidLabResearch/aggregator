package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

var client = &http.Client{} // restored global HTTP client
var solidAuth *SolidAuth    // restored global SolidAuth instance

const maxConcurrentRequestsPerEndpoint = 30

type endpointThrottler struct {
	mu         sync.Mutex
	semaphores map[string]chan struct{}
}

var throttler = &endpointThrottler{
	semaphores: make(map[string]chan struct{}),
}

func (et *endpointThrottler) acquire(endpoint string) {
	et.mu.Lock()
	sem, exists := et.semaphores[endpoint]
	if !exists {
		sem = make(chan struct{}, maxConcurrentRequestsPerEndpoint)
		et.semaphores[endpoint] = sem
	}
	et.mu.Unlock()

	sem <- struct{}{}
}

func (et *endpointThrottler) release(endpoint string) {
	et.mu.Lock()
	sem, exists := et.semaphores[endpoint]
	et.mu.Unlock()

	if exists {
		<-sem
	}
}

func getEndpoint(u *url.URL) string {
	return u.Scheme + "://" + u.Host
}

func throttledDo(req *http.Request) (*http.Response, error) {
	endpoint := getEndpoint(req.URL)

	throttler.acquire(endpoint)
	defer throttler.release(endpoint)

	return client.Do(req)
}

type claimToken struct {
	ClaimToken       string `json:"claim_token"`
	ClaimTokenFormat string `json:"claim_token_format"`
}

type permission struct {
	ResourceID     string   `json:"resource_id"`
	ResourceScopes []string `json:"resource_scopes"`
}

type requiredClaim struct {
	ClaimTokenFormat string   `json:"claim_token_format"`
	Issuer           string   `json:"issuer"`
	DerivationID     string   `json:"derivation_resource_id"`
	ResourceID       string   `json:"resource_id"`
	ResourceScopes   []string `json:"resource_scopes"`
	Details          struct {
		Issuer         string   `json:"issuer"`
		ResourceID     string   `json:"resource_id"`
		ResourceScopes []string `json:"resource_scopes"`
	} `json:"details"`
}

type uma2Config struct {
	TokenEndpoint                string `json:"token_endpoint"`
	ResourceRegistrationEndpoint string `json:"resource_registration_endpoint"`
}

// fetchAccessToken performs UMA token acquisition with recursive claim gathering on 403.
// Returns access token, token type, optional derivation resource id, and expires_in.
func fetchAccessToken(tokenEndpoint string, request interface{}, claims []claimToken) (string, string, string, ManagementAccessToken, int, error) {
	// Initialize with single ID token claim if none provided.
	if claims == nil || len(claims) == 0 {
		idTok, err := solidAuth.CreateClaimToken()
		if err != nil {
			return "", "", "", ManagementAccessToken{}, 0, fmt.Errorf("failed to create initial claim token: %w", err)
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
		return "", "", "", ManagementAccessToken{}, 0, fmt.Errorf("unsupported request type for fetchAccessToken: %T", request)
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return "", "", "", ManagementAccessToken{}, 0, err
	}

	tokenReq, err := createRequestWithRedirect("POST", tokenEndpoint, bytes.NewReader(payload))
	if err != nil {
		return "", "", "", ManagementAccessToken{}, 0, err
	}
	tokenReq.Header.Set("Content-Type", "application/json")
	resp, err := throttledDo(tokenReq)
	if err != nil {
		return "", "", "", ManagementAccessToken{}, 0, err
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
			return "", "", "", ManagementAccessToken{}, 0, fmt.Errorf("failed to decode forbidden response: %w", err)
		}
		updatedClaims, err := gatherClaims(claims, forbidden.RequiredClaims)
		if err != nil {
			return "", "", "", ManagementAccessToken{}, 0, err
		}
		return fetchAccessToken(tokenEndpoint, forbidden.Ticket, updatedClaims)
	}

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", "", "", ManagementAccessToken{}, 0, fmt.Errorf("failed to fetch access token: status %d body %s", resp.StatusCode, string(b))
	}

	var okResp struct {
		AccessToken           string                `json:"access_token"`
		TokenType             string                `json:"token_type"`
		DerivationResourceID  string                `json:"derivation_resource_id"`
		ManagementAccessToken ManagementAccessToken `json:"management_access_token"`
		ExpiresIn             int                   `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&okResp); err != nil {
		return "", "", "", ManagementAccessToken{}, 0, fmt.Errorf("failed to decode token response: %w", err)
	}

	if okResp.AccessToken == "" || okResp.TokenType == "" {
		return "", "", "", ManagementAccessToken{}, 0, fmt.Errorf("incomplete token response")
	}
	return okResp.AccessToken, okResp.TokenType, okResp.DerivationResourceID, okResp.ManagementAccessToken, okResp.ExpiresIn, nil
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
			issuer := firstNonEmpty(rc.Issuer, rc.Details.Issuer)
			resourceID := firstNonEmpty(rc.DerivationID, rc.ResourceID, rc.Details.ResourceID)
			resourceScopes := rc.ResourceScopes
			if len(resourceScopes) == 0 {
				resourceScopes = rc.Details.ResourceScopes
			}
			perm := []permission{{ResourceID: resourceID, ResourceScopes: resourceScopes}}
			at, _, _, _, _, err := fetchAccessToken(strings.TrimSuffix(issuer, "/")+"/token", perm, nil)
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

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func fetchUMA2Config(asUri string) (uma2Config, error) {
	reqConf, err := createRequestWithRedirect("GET", strings.TrimSuffix(asUri, "/")+"/.well-known/uma2-configuration", nil)
	if err != nil {
		return uma2Config{}, err
	}
	resp, err := throttledDo(reqConf)
	if err != nil {
		return uma2Config{}, fmt.Errorf("failed to get UMA2 configuration: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return uma2Config{}, fmt.Errorf("UMA2 configuration returned status %d", resp.StatusCode)
	}
	var config uma2Config
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return uma2Config{}, fmt.Errorf("failed to decode UMA2 config: %w", err)
	}
	if config.TokenEndpoint == "" {
		return uma2Config{}, fmt.Errorf("UMA2 configuration missing token_endpoint")
	}
	return config, nil
}

func updateUpstreamDerivationResource(config uma2Config, entry DerivationEntry, sourceURL string) error {
	if config.ResourceRegistrationEndpoint == "" {
		return fmt.Errorf("UMA2 configuration missing resource_registration_endpoint")
	}
	if entry.ManagementAccessToken.AccessToken == "" || entry.ManagementAccessToken.TokenType == "" {
		return fmt.Errorf("missing management_access_token")
	}

	payload := map[string]interface{}{
		"name":            entry.DerivationResourceID,
		"type":            "https://w3id.org/aggregator#DerivedResource",
		"description":     "Derived resource source for " + sourceURL,
		"resource_scopes": []string{"urn:knows:uma:scopes:derivation-read"},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	endpoint := strings.TrimRight(config.ResourceRegistrationEndpoint, "/") + "/" + url.PathEscape(entry.DerivationResourceID)
	req, err := createRequestWithRedirect("PUT", endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", entry.ManagementAccessToken.TokenType+" "+entry.ManagementAccessToken.AccessToken)
	resp, err := throttledDo(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upstream derivation resource update returned status %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

func deleteUpstreamDerivationResource(entry DerivationEntry) error {
	if entry.ResourceRegistrationURL == "" {
		return fmt.Errorf("missing resource registration URL")
	}
	if entry.ManagementAccessToken.AccessToken == "" || entry.ManagementAccessToken.TokenType == "" {
		return fmt.Errorf("missing management_access_token")
	}
	req, err := createRequestWithRedirect("DELETE", entry.ResourceRegistrationURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", entry.ManagementAccessToken.TokenType+" "+entry.ManagementAccessToken.AccessToken)
	resp, err := throttledDo(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upstream derivation resource delete returned status %d: %s", resp.StatusCode, string(b))
	}
	return nil
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
		return throttledDo(req)
	}
	// Attempt to use cached UMA token first
	method := req.Method
	resourceURL := req.URL.String()
	if tokenType, accessToken, ok := solidAuth.getUmaToken(method, resourceURL); ok {
		logrus.WithFields(logrus.Fields{"url": resourceURL}).Debug("Using cached UMA token")
		req.Header.Set("Authorization", fmt.Sprintf("%s %s", tokenType, accessToken))
		cachedResp, err := throttledDo(req)
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
	unauthenticatedResp, err := throttledDo(req)
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
		uma2Config, err := fetchUMA2Config(asUri)
		if err != nil {
			logrus.WithError(err).Warn("Failed to fetch UMA2 configuration")
			return unauthenticatedResp, nil
		}

		tokenEndpoint := uma2Config.TokenEndpoint

		accessToken, tokenType, derivationResourceId, managementToken, expiresIn, err := fetchAccessToken(tokenEndpoint, ticket, nil)
		if err != nil {
			return nil, err
		}
		// Store in cache before retry
		solidAuth.storeUmaToken(method, resourceURL, tokenType, accessToken, expiresIn)
		if derivationResourceId != "" {
			entry := DerivationEntry{
				SourceURL:               resourceURL,
				Issuer:                  asUri,
				DerivationResourceID:    derivationResourceId,
				ManagementAccessToken:   managementToken,
				ResourceRegistrationURL: strings.TrimRight(uma2Config.ResourceRegistrationEndpoint, "/") + "/" + url.PathEscape(derivationResourceId),
			}
			solidAuth.storeDerivation(resourceURL, entry)
			if err := updateUpstreamDerivationResource(uma2Config, entry, resourceURL); err != nil {
				logrus.WithFields(logrus.Fields{"source": resourceURL, "derivation_resource_id": derivationResourceId, "err": err}).Warn("Failed to update upstream derivation resource metadata")
			}
		}
		req.Header.Set("Authorization", fmt.Sprintf("%s %s", tokenType, accessToken))
		authorizedResp, err := throttledDo(req)
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
