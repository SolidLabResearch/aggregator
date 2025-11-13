package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/sirupsen/logrus"
)

type claim struct {
	GrantType        string `json:"grant_type"`
	Ticket           string `json:"ticket"`
	Scope            string `json:"scope"`
	ClaimToken       string `json:"claim_token"`
	ClaimTokenFormat string `json:"claim_token_format"`
}

var client = &http.Client{}
var solidAuth *SolidAuth // Global auth instance

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
		if newURL.Hostname() == "host.minikube.internal" && (originalHost == "localhost:3000" || strings.HasPrefix(originalHost, "localhost:")) {
			req.Host = originalHost
			logrus.WithFields(logrus.Fields{"original_host": originalHost}).Debug("🔧 Setting Host header to original value")
		}
	}

	// If no authentication is configured, just pass through the request
	if solidAuth == nil {
		return client.Do(req)
	}

	// Do UMA flow with authentication
	unauthenticatedResp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if unauthenticatedResp.StatusCode == http.StatusUnauthorized {
		defer unauthenticatedResp.Body.Close()
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
		defer uma2ConfigResponse.Body.Close()

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

		claimTokenFormat := "http://openid.net/specs/openid-connect-core-1_0.html#IDToken"
		claimTokenStr, err := solidAuth.CreateClaimToken(tokenEndpoint)
		if err != nil {
			return nil, fmt.Errorf("⚠️ Failed to create Solid OIDC claim: %v", err)
		}

		jsonBody, err := json.Marshal(claim{
			GrantType:        "urn:ietf:params:oauth:grant-type:uma-ticket",
			Ticket:           ticket,
			Scope:            "urn:knows:uma:scopes:derivation-creation",
			ClaimToken:       claimTokenStr,
			ClaimTokenFormat: claimTokenFormat,
		})
		if err != nil {
			return nil, err
		}

		tokenReq, err := createRequestWithRedirect("POST", tokenEndpoint, bytes.NewReader(jsonBody))
		if err != nil {
			return nil, err
		}
		tokenReq.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(tokenReq)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		logrus.WithFields(logrus.Fields{"status_code": resp.StatusCode}).Debug("Received response from token endpoint")
		if resp.StatusCode != http.StatusOK {
			logrus.WithFields(logrus.Fields{"url": req.URL.String()}).Warn("Unauthorized to access resource")
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Status:     http.StatusText(http.StatusUnauthorized),
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		}
		var asResponse map[string]string
		err = json.NewDecoder(resp.Body).Decode(&asResponse)
		if err != nil {
			return nil, err
		}

		accessToken, ok := asResponse["access_token"]
		if !ok {
			return nil, fmt.Errorf("access_token not found in response")
		}
		tokenType, ok := asResponse["token_type"]
		if !ok {
			return nil, fmt.Errorf("token_type not found in response")
		}
		derivationResourceId, ok := asResponse["derivation_resource_id"]
		// TODO if not present only the aggregator owner can access the derivation result
		if !ok {
			return nil, fmt.Errorf("derivation_resource_id not found in response")
		}

		req.Header.Set("Authorization", fmt.Sprintf("%s %s", tokenType, accessToken))
		authorizedResp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		authorizedResp.Header.Set("X-Derivation-Resource-Id", derivationResourceId)
		authorizedResp.Header.Set("X-Derivation-Issuer", asUri)
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

func parseJwt(token string) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	var payload map[string]interface{}
	err = json.Unmarshal(decoded, &payload)
	if err != nil {
		return nil, err
	}

	return payload, nil
}
