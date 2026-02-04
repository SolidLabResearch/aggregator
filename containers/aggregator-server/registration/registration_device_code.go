package registration

import (
	"aggregator/instance"
	"aggregator/model"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/jwt"
	"github.com/sirupsen/logrus"
)

type DeviceSession struct {
	AggregatorID        string
	AuthorizationServer string
	DeviceCode          string
	ExpiresAt           time.Time
	Interval            time.Duration
}

var deviceSessions = make(map[string]*DeviceSession)
var sessionsLock sync.Mutex

type DeviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
}

func handleDeviceCodeFlow(w http.ResponseWriter, req model.RegistrationRequest) {
	if req.DeviceCode == "" {
		handleDeviceCodeFlowStart(w, req)
	} else {
		handleDeviceCodeFlowFinish(w, req)
	}
}

func handleDeviceCodeFlowStart(w http.ResponseWriter, req model.RegistrationRequest) {
	logrus.Debugf("Received device code start request: AggregatorID=%s, AuthorizationServer=%s",
		req.AggregatorID, req.AuthorizationServer)

	// Get OIDC configuration
	oidcConfig, err := fetchOIDCConfig(model.AuthServer)
	if err != nil {
		logrus.WithError(err).Warnf("Unable to fetch OIDC configuration for %s", model.AuthServer)
		http.Error(w, "Authorization failed", http.StatusInternalServerError)
		return
	}
	if oidcConfig.DeviceAuthorizationEndpoint == "" {
		logrus.Warn("Missing device authorization endpoint in OIDC config")
		http.Error(w, "Authorization failed", http.StatusInternalServerError)
		return
	}
	logrus.Debugf("OIDC Device Authorization Endpoint: %s", oidcConfig.DeviceAuthorizationEndpoint)

	// Request device code
	data := fmt.Sprintf("client_id=%s&client_secret=%s&scope=openid offline_access", model.ClientId, model.ClientSecret)
	resp, err := http.Post(
		oidcConfig.DeviceAuthorizationEndpoint,
		"application/x-www-form-urlencoded",
		bytes.NewBufferString(data),
	)
	if err != nil {
		logrus.WithError(err).Warn("Failed to request device code from authorization server")
		http.Error(w, "Unable to authorize", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		logrus.Warn("Failed to request device code from authorization server")
		logrus.Debugf("Raw device code response with code %s: %s", resp.Status, string(body))
		http.Error(w, "Unable to authorize", http.StatusInternalServerError)
		return
	}
	var deviceResp DeviceCodeResponse
	if err := json.Unmarshal(body, &deviceResp); err != nil {
		logrus.WithError(err).Warnf("Failed to parse device code response: %s", string(body))
		http.Error(w, "Unable to authorize", http.StatusInternalServerError)
		return
	}

	logrus.Debugf("Received device code response: DeviceCode=%s, UserCode=%s, VerificationURI=%s, ExpiresIn=%d, Interval=%d",
		deviceResp.DeviceCode, deviceResp.UserCode, deviceResp.VerificationURI, deviceResp.ExpiresIn, deviceResp.Interval)

	// Store device session metadata
	sessionsLock.Lock()
	deviceSessions[deviceResp.DeviceCode] = &DeviceSession{
		AggregatorID:        req.AggregatorID,
		AuthorizationServer: req.AuthorizationServer,
		DeviceCode:          deviceResp.DeviceCode,
		ExpiresAt:           time.Now().Add(time.Duration(deviceResp.ExpiresIn) * time.Second),
		Interval:            time.Duration(deviceResp.Interval) * time.Second,
	}
	sessionsLock.Unlock()
	logrus.Debugf("Stored device session for DeviceCode=%s", deviceResp.DeviceCode)

	// Respond with user instructions
	respJSON := map[string]string{
		"device_code":      deviceResp.DeviceCode,
		"user_code":        deviceResp.UserCode,
		"verification_uri": deviceResp.VerificationURI,
		"expires_in":       fmt.Sprintf("%d", deviceResp.ExpiresIn),
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(respJSON); err != nil {
		logrus.WithError(err).Error("Failed to write device code start response")
	}
	logrus.Debugf("Sent device code start response for DeviceCode=%s", deviceResp.DeviceCode)
}

func handleDeviceCodeFlowFinish(w http.ResponseWriter, req model.RegistrationRequest) {
	logrus.Debugf("Starting device code flow finish: DeviceCode=%s, AggregatorID=%s, AuthorizationServer=%s",
		req.DeviceCode, req.AggregatorID, req.AuthorizationServer)

	// Get device_code
	deviceCode := req.DeviceCode

	// Retrieve session metadata
	sessionsLock.Lock()
	session, ok := deviceSessions[deviceCode]
	sessionsLock.Unlock()
	if !ok {
		logrus.Warnf("Invalid or expired device_code: %s", deviceCode)
		http.Error(w, "Invalid or expired device_code", http.StatusBadRequest)
		return
	}

	// Check expiration
	if time.Now().After(session.ExpiresAt) {
		logrus.Infof("Device code expired for DeviceCode=%s", deviceCode)
		http.Error(w, "Device code expired", http.StatusUnauthorized)
		return
	}

	// Fetch OIDC configuration
	oidcConfig, err := fetchOIDCConfig(model.AuthServer)
	if err != nil {
		logrus.WithError(err).Warnf("Unable to fetch OIDC configuration for %s", model.AuthServer)
		http.Error(w, "Authorization failed", http.StatusInternalServerError)
		return
	}
	if oidcConfig.TokenEndpoint == "" {
		logrus.Warn("Missing token endpoint in OIDC configuration")
		http.Error(w, "Authorization failed", http.StatusInternalServerError)
		return
	}
	logrus.Debugf("Using token endpoint: %s", oidcConfig.TokenEndpoint)

	// Poll Authz server token endpoint until authorized
	var tok TokenResponse
	for time.Now().Before(session.ExpiresAt) {
		data := fmt.Sprintf(
			"grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=%s&client_id=%s&client_secret=%s",
			session.DeviceCode, model.ClientId, model.ClientSecret,
		)
		resp, err := http.Post(oidcConfig.TokenEndpoint, "application/x-www-form-urlencoded", bytes.NewBufferString(data))
		if err != nil {
			logrus.WithError(err).Warn("Failed to poll token endpoint")
			http.Error(w, "Token request failed", http.StatusInternalServerError)
			return
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			if err := json.Unmarshal(body, &tok); err != nil {
				logrus.WithError(err).Warnf("Failed to parse token response: %s", string(body))
				http.Error(w, "Failed to parse token", http.StatusInternalServerError)
				return
			}
			logrus.Infof("Successfully received access token for DeviceCode=%s", deviceCode)
			break
		} else {
			var errResp map[string]interface{}
			_ = json.Unmarshal(body, &errResp)
			switch errResp["error"] {
			case "authorization_pending":
				logrus.Debugf("Authorization pending for DeviceCode=%s, retrying in %s", deviceCode, session.Interval)
				time.Sleep(session.Interval)
				continue
			case "expired_token":
				logrus.Infof("Device code expired while polling: %s", deviceCode)
				http.Error(w, "Device code expired", http.StatusUnauthorized)
				return
			default:
				logrus.Warnf("Unexpected token error for DeviceCode=%s: %s", deviceCode, string(body))
				http.Error(w, fmt.Sprintf("Token request failed: %s", string(body)), http.StatusInternalServerError)
				return
			}
		}
	}

	// Validate access token
	userID, err := validateDeviceToken(tok.AccessToken)
	if err != nil {
		logrus.WithError(err).Warnf("Invalid access token for DeviceCode=%s", deviceCode)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	logrus.Debugf("Token validated successfully for user: %s", userID)

	// Deploy aggregator instance
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tokenExpiry := time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second).UTC().Format(time.RFC3339)

	aggregatorID, err := instance.DeployAggregator(
		tok.IDToken,
		oidcConfig.TokenEndpoint,
		tok.AccessToken,
		tok.RefreshToken,
		tokenExpiry,
		userID,
		session.AuthorizationServer,
		ctx,
	)
	if err != nil {
		logrus.WithError(err).Error("Failed to deploy aggregator instance")
		http.Error(w, "Failed to deploy aggregator", http.StatusInternalServerError)
		return
	}
	logrus.Infof("Aggregator deployed successfully: AggregatorID=%s", aggregatorID)

	// Create aggregator record
	inst := createAggregatorInstanceRecord(
		session.AggregatorID,
		"device_code",
		session.AuthorizationServer,
		aggregatorID,
		tok.IDToken,
		tok.AccessToken,
		tok.RefreshToken,
	)

	// Remove session from store
	sessionsLock.Lock()
	delete(deviceSessions, deviceCode)
	sessionsLock.Unlock()
	logrus.Debugf("Removed device session for DeviceCode=%s", deviceCode)

	// Respond with aggregator URL
	response := model.RegistrationResponse{
		AggregatorId: inst.AggregatorID,
		Aggregator:   inst.BaseURL,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logrus.WithError(err).Error("Failed to write response")
	} else {
		logrus.Infof("Device code flow finished successfully for DeviceCode=%s, AggregatorID=%s", deviceCode, inst.AggregatorID)
	}
}

func validateDeviceToken(tokenString string) (string, error) {
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

	// Verify issuer
	if issStr != model.AuthServer {
		logrus.Warnf("Token issuer mismatch: expected %s, got %s", model.AuthServer, issStr)
		return "", errors.New("token issuer mismatch")
	}

	// Verify azp claim
	azp, ok := verifiedToken.Get("azp")
	if !ok {
		logrus.Warn("Token missing azp claim")
		return "", errors.New("token missing azp claim")
	}
	azpStr, ok := azp.(string)
	if !ok || azpStr != model.ClientId {
		logrus.Warnf("Token azp mismatch: expected %s, got %v", model.ClientId, azp)
		return "", errors.New("token not issued for this client")
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
