package main

import (
	"bytes"
	"egress-uma/model"
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

// TokenResponse represents the RPT response from the Authorization Server
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in,omitempty"`
}

// RequestWithUMA performs the UMA flow for a request to an external URL
func RequestWithUMA(client *http.Client, r *http.Request) (*http.Response, error) {
	logrus.WithFields(logrus.Fields{
		"method": r.Method,
		"url":    r.URL.String(),
	}).Info("Starting UMA request flow")

	var bodyBytes []byte
	if r.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(r.Body)
		if err != nil {
			logrus.WithError(err).Error("Failed to read request body")
			return nil, err
		}
		logrus.WithField("body_size", len(bodyBytes)).Debug("Read request body")
	}

	dest := &url.URL{
		Scheme:   requestScheme(r),
		Host:     requestHost(r),
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}

	logrus.WithField("target_url", dest.String()).Info("Preparing initial request")

	// --- Initial request (no UMA ticket)
	ticketlessReq, err := http.NewRequest(r.Method, dest.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		logrus.WithError(err).Error("Failed to create initial request")
		return nil, err
	}
	ticketlessReq.Header = r.Header.Clone()

	model.LogHeaders("Initial request headers", ticketlessReq.Header)

	resp, err := client.Do(ticketlessReq)
	if err != nil {
		logrus.WithError(err).Error("Initial request failed")
		return nil, err
	}

	logrus.WithField("status", resp.StatusCode).Info("Initial response received")

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		logrus.Info("Request succeeded without UMA")
		return resp, nil
	}
	defer resp.Body.Close()

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if wwwAuth == "" {
		logrus.Warn("No WWW-Authenticate header present; returning original response")
		return resp, nil
	}

	logrus.Debug("Parsing WWW-Authenticate header")

	tokenEndpoint, ticket, err := parseAuthenticateHeader(wwwAuth)
	if err != nil {
		logrus.WithError(err).Error("Failed to parse WWW-Authenticate header")
		return nil, err
	}

	logrus.WithFields(logrus.Fields{
		"token_endpoint": tokenEndpoint,
		"ticket":         ticket,
	}).Debug("Parsed UMA challenge")

	// --- Get claim token
	claimToken, err := getAccessToken()
	if err != nil {
		logrus.WithError(err).Error("Failed to get claim token")
		return nil, err
	}

	logrus.Debug("Obtained claim token")

	// --- UMA token request
	umaRequest := map[string]string{
		"grant_type":         "urn:ietf:params:oauth:grant-type:uma-ticket",
		"ticket":             ticket,
		"claim_token":        claimToken,
		"claim_token_format": "http://openid.net/specs/openid-connect-core-1_0.html#IDToken",
	}

	umaBody, err := json.Marshal(umaRequest)
	if err != nil {
		logrus.WithError(err).Error("Failed to marshal UMA request body")
		return nil, err
	}

	logrus.WithField("endpoint", tokenEndpoint).Info("Requesting UMA token")

	umaReq, err := http.NewRequest("POST", tokenEndpoint, bytes.NewReader(umaBody))
	if err != nil {
		logrus.WithError(err).Error("Failed to create UMA token request")
		return nil, err
	}
	umaReq.Header = make(http.Header)
	umaReq.Header.Set("Content-Type", "application/json")

	model.LogHeaders("UMA token request headers", umaReq.Header)

	umaResp, err := client.Do(umaReq)
	if err != nil {
		logrus.WithError(err).Error("UMA token request failed")
		return nil, err
	}
	defer umaResp.Body.Close()

	logrus.WithField("status", umaResp.StatusCode).Info("UMA token response received")

	if umaResp.StatusCode < 200 || umaResp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(umaResp.Body)
		logrus.WithFields(logrus.Fields{
			"status": umaResp.StatusCode,
			"body":   string(bodyBytes),
		}).Error("UMA token request returned error")
		return nil, errors.New(string(bodyBytes))
	}

	var rpt TokenResponse
	if err := json.NewDecoder(umaResp.Body).Decode(&rpt); err != nil {
		logrus.WithError(err).Error("Failed to decode UMA token response")
		return nil, err
	}

	logrus.Debug("Successfully decoded UMA token")

	// --- Final request with UMA token
	ticketedReq, err := http.NewRequest(r.Method, dest.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		logrus.WithError(err).Error("Failed to create ticketed request")
		return nil, err
	}

	ticketedReq.Header = r.Header.Clone()
	ticketedReq.Header.Set("Authorization", rpt.TokenType+" "+rpt.AccessToken)

	model.LogHeaders("Final request headers", ticketedReq.Header)

	logrus.Info("Retrying request with UMA token")

	finalResp, err := client.Do(ticketedReq)
	if err != nil {
		logrus.WithError(err).Error("Final request with UMA token failed")
		return nil, err
	}

	logrus.WithField("status", finalResp.StatusCode).Info("Final response received")

	return finalResp, nil
}

func requestScheme(r *http.Request) string {
	if r.URL != nil && r.URL.Scheme != "" {
		return r.URL.Scheme
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func requestHost(r *http.Request) string {
	if r.URL != nil && r.URL.Host != "" {
		return r.URL.Host
	}
	return r.Host
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
	resp, err := model.HttpClient.Get(asURI + "/.well-known/uma2-configuration")
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
