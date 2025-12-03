package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/sirupsen/logrus"
)

// UMAConfig represents the UMA server configuration
type UMAConfig struct {
	TokenEndpoint string `json:"token_endpoint"`
}

// UMAResponse represents the RPT response from the Authorization Server
type UMAResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in,omitempty"`
}

// RequestWithUMA performs the UMA flow for a request to an external URL
func RequestWithUMA(client *http.Client, r *http.Request) (*http.Response, error) {
	// --- Incoming request ---
	logrus.WithFields(logrus.Fields{
		"url":     r.URL.String(),
		"method":  r.Method,
		"headers": r.Header,
	}).Info("Incoming request received for UMA enforcement")

	// --- Step 1: Build destination URL ---
	dest := &url.URL{
		Scheme:   "http",
		Host:     r.Host,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}

	logrus.WithFields(logrus.Fields{
		"dest_url": dest.String(),
	}).Info("Constructed upstream destination URL")

	// --- Step 1a: First request with NO Authorization ---
	ticketlessReq, err := http.NewRequest(r.Method, dest.String(), r.Body)
	if err != nil {
		logrus.WithError(err).Error("Failed to build ticketless upstream request")
		return nil, err
	}

	copySafeHeaders(ticketlessReq.Header, r.Header)

	logrus.WithFields(logrus.Fields{
		"method":  ticketlessReq.Method,
		"url":     ticketlessReq.URL.String(),
		"headers": ticketlessReq.Header,
	}).Info("Sending ticketless request to upstream UMA resource server")

	resp, err := client.Do(ticketlessReq)
	if err != nil {
		logrus.WithError(err).Error("Upstream request failed (ticketless)")
		return nil, err
	}

	logrus.WithFields(logrus.Fields{
		"status": resp.StatusCode,
	}).Info("Received response from upstream (ticketless request)")

	// --- Step 1b: Success without UMA ---
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		logrus.Info("UMA not required: upstream accepted request without Authorization")
		return resp, nil
	}
	defer resp.Body.Close()

	// --- Step 2: Check UMA Challenge ---
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if wwwAuth == "" {
		logrus.Warn("Upstream rejected request but did NOT provide WWW-Authenticate header. Cannot perform UMA.")
		return resp, nil
	}

	logrus.WithFields(logrus.Fields{
		"header": wwwAuth,
	}).Info("Received WWW-Authenticate challenge")

	tokenEndpoint, ticket, err := parseAuthenticateHeader(wwwAuth)
	if err != nil {
		logrus.WithError(err).Error("Failed to parse UMA WWW-Authenticate header")
		return nil, err
	}

	logrus.WithFields(logrus.Fields{
		"token_endpoint": tokenEndpoint,
		"ticket":         ticket,
	}).Info("Parsed UMA challenge: obtained ticket and token endpoint")

	// --- Step 3: Create claim token ---
	claimToken, err := createClaimToken()
	if err != nil {
		logrus.WithError(err).Error("Failed to create claim token for UMA")
		return nil, err
	}

	logrus.Info("Successfully created OIDC claim token for UMA")

	// --- Step 4: Request UMA token (RPT) ---
	umaRequest := map[string]string{
		"grant_type":         "urn:ietf:params:oauth:grant-type:uma-ticket",
		"ticket":             ticket,
		"claim_token":        claimToken,
		"claim_token_format": "http://openid.net/specs/openid-connect-core-1_0.html#IDToken",
	}
	umaBody, _ := json.Marshal(umaRequest)

	umaReq, _ := http.NewRequest("POST", tokenEndpoint, bytes.NewReader(umaBody))
	umaReq.Header.Set("Content-Type", "application/json")

	logrus.WithFields(logrus.Fields{
		"url":     tokenEndpoint,
		"payload": string(umaBody),
	}).Info("Requesting UMA RPT token")

	umaResp, err := client.Do(umaReq)
	if err != nil {
		logrus.WithError(err).Error("UMA token request failed")
		return nil, err
	}
	defer umaResp.Body.Close()

	logrus.WithFields(logrus.Fields{
		"status": umaResp.StatusCode,
	}).Info("Received UMA token endpoint response")

	if umaResp.StatusCode < 200 || umaResp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(umaResp.Body)
		logrus.WithFields(logrus.Fields{
			"status": umaResp.StatusCode,
			"body":   string(bodyBytes),
		}).Error("UMA token request failed: upstream AS returned error")

		return nil, errors.New("UMA token request failed: " + string(bodyBytes))
	}

	var rpt UMAResponse
	if err := json.NewDecoder(umaResp.Body).Decode(&rpt); err != nil {
		logrus.WithError(err).Error("Failed to decode UMA token endpoint response")
		return nil, err
	}

	logrus.WithFields(logrus.Fields{
		"token_type": rpt.TokenType,
	}).Info("Successfully obtained UMA RPT")

	// --- Step 5: Retry the request with the RPT token ---
	ticketedReq, err := http.NewRequest(r.Method, dest.String(), r.Body)
	if err != nil {
		logrus.WithError(err).Error("Failed to create ticketed upstream request")
		return nil, err
	}
	copySafeHeaders(ticketedReq.Header, r.Header)
	ticketedReq.Header.Set("Authorization", rpt.TokenType+" "+rpt.AccessToken)

	logrus.WithFields(logrus.Fields{
		"url":     ticketedReq.URL.String(),
		"headers": ticketedReq.Header,
	}).Info("Retrying request with UMA RPT token")

	return client.Do(ticketedReq)
}

// parseAuthenticateHeader parses the WWW-Authenticate header and fetches UMA config
func parseAuthenticateHeader(wwwAuthHeader string) (tokenEndpoint string, ticket string, err error) {
	// Remove "UMA " prefix
	header := strings.TrimPrefix(wwwAuthHeader, "UMA ")

	// Split key=value pairs
	pairs := strings.Split(header, ", ")
	params := map[string]string{}
	for _, pair := range pairs {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := kv[0]
		value := strings.Trim(kv[1], `"`) // remove quotes
		params[key] = value
	}

	asURI, ok1 := params["as_uri"]
	ticket, ok2 := params["ticket"]
	if !ok1 || !ok2 {
		err = errors.New("WWW-Authenticate header missing as_uri or ticket")
		return
	}

	// Fetch UMA server configuration from as_uri
	config, err := getUMAConfig(asURI)
	if err != nil {
		return
	}

	return config.TokenEndpoint, ticket, nil
}

// getUMAConfig fetches UMA server config (token endpoint) from its .well-known endpoint
func getUMAConfig(asURI string) (UMAConfig, error) {
	// Usually the UMA config is at /.well-known/uma2-configuration
	resp, err := http.Get(asURI + "/.well-known/uma2-configuration")
	if err != nil {
		return UMAConfig{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return UMAConfig{}, errors.New("failed to fetch UMA config")
	}

	var config UMAConfig
	err = json.NewDecoder(resp.Body).Decode(&config)
	if err != nil {
		return UMAConfig{}, err
	}

	return config, nil
}

func copySafeHeaders(dst, src http.Header) {
	hopByHop := map[string]bool{
		"Connection":          true,
		"Keep-Alive":          true,
		"Proxy-Authenticate":  true,
		"Proxy-Authorization": true,
		"Te":                  true,
		"Trailers":            true,
		"Transfer-Encoding":   true,
		"Upgrade":             true,
	}

	for k, vv := range src {
		if hopByHop[http.CanonicalHeaderKey(k)] {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
