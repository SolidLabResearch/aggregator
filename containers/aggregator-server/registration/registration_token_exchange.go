package registration

import (
	"aggregator/instance"
	"aggregator/model"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/jwt"
	"github.com/sirupsen/logrus"
)

func handleTokenExchangeFlow(w http.ResponseWriter, req model.RegistrationRequest, subjectToken string) {
	// Get OIDC configuration
	oidcConfig, err := fetchOIDCConfig(model.OIDCServer)
	if err != nil {
		logrus.WithError(err).Warnf("Unable to fetch OIDC configuration for %s", model.OIDCServer)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if oidcConfig.TokenEndpoint == "" {
		logrus.Warn("Missing token endpoint in OIDC config")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	logrus.Debugf("OIDC Token Endpoint: %s", oidcConfig.TokenEndpoint)

	// Do the token exchange
	formData := url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":        {subjectToken},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:access_token"},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:refresh_token"},
		"scope":                {"openid profile offline_access"},
	}

	// Create the HTTP request for token exchange
	exchangeReq, err := http.NewRequest(http.MethodPost, oidcConfig.TokenEndpoint, strings.NewReader(formData.Encode()))
	if err != nil {
		logrus.WithError(err).Warnf("Unable to create token exchange request for %s", oidcConfig.TokenEndpoint)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	exchangeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	exchangeReq.SetBasicAuth(model.OIDCClientId, model.OIDCClientSecret)

	// Execute the token exchange request
	resp, err := model.HttpClient.Do(exchangeReq)
	if err != nil {
		logrus.WithError(err).Warnf("Unable to execute token exchange request for %s", oidcConfig.TokenEndpoint)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.WithError(err).Warn("Failed to read token exchange response body")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if resp.StatusCode != http.StatusOK {
		logrus.WithFields(logrus.Fields{
			"status": resp.StatusCode,
			"body":   string(body),
		}).Warn("Token exchange request failed")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Parse the token exchange response
	var tokenResponse TokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		logrus.WithError(err).Warn("Failed to decode token exchange response")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	//logrus.Debugf("Token exchange response: %+v", tokenResponse)

	// Validate the exchanged token
	subject, err := validateExchangedToken(tokenResponse.AccessToken)
	if err != nil {
		logrus.WithError(err).Warn("Exchanged token validation failed")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	logrus.Debugf("Exchanged token validated successfully, subject: %s", subject)

	var aggregatorID string
	var baseURL string
	if req.AggregatorID != "" {
		// Check if aggregator exists and user is authorized to update it
		inst, err := instance.GetAggregatorInstance(aggregatorID)
		if err != nil {
			logrus.WithError(err).Warnf("Aggregator not found: %s", req.AggregatorID)
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}

		if !inst.HasOwnership(subject) {
			logrus.WithField("requester", subject).Warnf("Ownership check failed for aggregator %s", req.AggregatorID)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		aggregatorID = inst.AggregatorID
		baseURL = inst.BaseURL
		logrus.Debugf("Ownership verified for aggregator %s by user %s", req.AggregatorID, subject)
	}

	// Upsert tokens
	if err := upsertTokens(
		subject,
		tokenResponse,
		model.OIDCServer,
		model.OIDCClientId,
		model.OIDCClientSecret,
	); err != nil {
		logrus.WithError(err).Warn("Failed to upsert tokens")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if aggregatorID != "" {
		// Deploy aggregator
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		aggregatorID, err := instance.DeployAggregator(
			subject,
			req.AuthorizationServer,
			"",
			ctx,
		)
		if err != nil {
			logrus.WithError(err).Warn("Failed to deploy aggregator")
			http.Error(w, "Aggregator deployment failed", http.StatusInternalServerError)
			return
		}

		// Create aggregator record
		inst := instance.CreateAggregatorInstanceRecord(
			subject,
			"token_exchange",
			req.AuthorizationServer,
			aggregatorID,
		)
		baseURL = inst.BaseURL

		logrus.Debugf("Aggregator deployed successfully at: %s", inst.BaseURL)
	}

	// Respond with aggregator details
	regResp := model.RegistrationResponse{
		AggregatorID: aggregatorID,
		Aggregator:   baseURL,
		Subject:      subject,
		IDP:          model.OIDCServer,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(regResp)
}

func validateExchangedToken(tokenString string) (string, error) {
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

	// Verify issuer
	if issStr != model.OIDCServer {
		logrus.Warnf("Token issuer mismatch: expected %s, got %s", model.OIDCServer, issStr)
		return "", errors.New("token issuer mismatch")
	}

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

	// Verify azp claim
	azp, ok := verifiedToken.Get("azp")
	if !ok {
		logrus.Warn("Token missing azp claim")
		return "", errors.New("token missing azp claim")
	}
	azpStr, ok := azp.(string)
	if !ok || azpStr != model.OIDCClientId {
		logrus.Warnf("Token azp mismatch: expected %s, got %v", model.OIDCClientId, azp)
		return "", errors.New("token not issued for this client")
	}

	// Verify scope claims
	scope, ok := verifiedToken.Get("scope")
	if !ok {
		logrus.Warn("Token missing scope claim")
		return "", errors.New("token missing scope claim")
	}
	scopeStr, ok := scope.(string)
	if !ok || !strings.Contains(scopeStr, "openid") || !strings.Contains(scopeStr, "offline_access") {
		logrus.Warnf("Token missing required scopes (openid, offiline_access): %v", scope)
		return "", errors.New("token missing required scopes (openid, offline_access)")
	}

	// Verify sub claim exists
	sub, ok := verifiedToken.Get("sub")
	if !ok {
		logrus.Warn("Token missing sub claim")
		return "", errors.New("token missing sub claim")
	}
	subStr, ok := sub.(string)
	if !ok || subStr == "" {
		logrus.Warn("Invalid sub claim")
		return "", errors.New("invalid sub claim")
	}

	logrus.Debugf("Token validation passed, user ID: %s", subStr)
	return subStr, nil
}
