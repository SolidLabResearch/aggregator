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
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/jwt"
	"github.com/sirupsen/logrus"
)

// Device code flow response structs
type DeviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// DeviceFlowStatus represents the current status of a device code flow session
type DeviceFlowStatus string

const (
	StatusPending   DeviceFlowStatus = "pending"   // waiting for tokens
	StatusDeploying DeviceFlowStatus = "deploying" // creating aggregator
	StatusUpdating  DeviceFlowStatus = "updating"  // updating existing aggregator with new tokens
	StatusDone      DeviceFlowStatus = "done"
	StatusError     DeviceFlowStatus = "error"
)

// DeviceSession holds the state of an ongoing device code flow registration
type DeviceSession struct {
	State               string
	AggregatorID        string
	AuthorizationServer string

	DeviceCode string
	Interval   time.Duration
	ExpiresAt  time.Time

	Status DeviceFlowStatus
	Error  string

	// Result fields
	ResultAggregatorID string
	ResultBaseURL      string
	ResultSubject      string
}

var deviceSessions = make(map[string]*DeviceSession)
var sessionsLock sync.Mutex

// handleDeviceCodeFlow routes the request to either start or finish the device code flow based on presence of state
func handleDeviceCodeFlow(w http.ResponseWriter, req model.RegistrationRequest) {
	if req.State == "" {
		handleDeviceCodeFlowStart(w, req)
	} else {
		handleDeviceCodeFlowFinish(w, req)
	}
}

// handleDeviceCodeFlowStart initiates the device code flow by requesting a device code
// from the authorization server and returning user instructions
func handleDeviceCodeFlowStart(w http.ResponseWriter, req model.RegistrationRequest) {
	logrus.Debugf("Received device code start request: AggregatorID=%s, AuthorizationServer=%s",
		req.AggregatorID, req.AuthorizationServer)

	state := generateState()

	// Get OIDC configuration
	oidcConfig, err := fetchOIDCConfig(model.OIDCServer)
	if err != nil {
		logrus.WithError(err).Warnf("Unable to fetch OIDC configuration for %s", model.OIDCServer)
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
	data := fmt.Sprintf("client_id=%s&client_secret=%s&scope=openid offline_access", model.OIDCClientId, model.OIDCClientSecret)
	resp, err := model.HttpClient.Post(
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
	session := &DeviceSession{
		State:               state,
		AggregatorID:        req.AggregatorID,
		AuthorizationServer: req.AuthorizationServer,
		DeviceCode:          deviceResp.DeviceCode,
		Interval:            time.Duration(deviceResp.Interval) * time.Second,
		ExpiresAt:           time.Now().Add(time.Duration(deviceResp.ExpiresIn) * time.Second),
		Status:              StatusPending,
	}

	sessionsLock.Lock()
	deviceSessions[state] = session
	sessionsLock.Unlock()
	logrus.Debugf("Stored device session for DeviceCode=%s", deviceResp.DeviceCode)

	// Start background process to monitor device code flow completion
	go processDeviceCodeFlow(session, oidcConfig)

	// Respond with user instructions
	respJSON := map[string]string{
		"state":                     state,
		"user_code":                 deviceResp.UserCode,
		"verification_uri":          deviceResp.VerificationURI,
		"verification_uri_complete": fmt.Sprintf("%s?user_code=%s", deviceResp.VerificationURI, deviceResp.UserCode),
		"expires_in":                fmt.Sprintf("%d", deviceResp.ExpiresIn),
		"interval":                  fmt.Sprintf("%d", deviceResp.Interval),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	if err := json.NewEncoder(w).Encode(respJSON); err != nil {
		logrus.WithError(err).Error("Failed to write device code start response")
		http.Error(w, "Unable to authorize", http.StatusInternalServerError)
		return
	}
	logrus.Debugf("Sent device code start response for DeviceCode=%s", deviceResp.DeviceCode)
}

// processDeviceCodeFlow continuously polls the token endpoint until the user completes authorization or the device code expires,
// then deploys the aggregator if successful
func processDeviceCodeFlow(session *DeviceSession, oidcConfig *model.OIDCConfig) {
	var tok TokenResponse

	for time.Now().Before(session.ExpiresAt) {

		form := url.Values{}
		form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
		form.Set("device_code", session.DeviceCode)

		req, _ := http.NewRequest("POST", oidcConfig.TokenEndpoint, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(model.OIDCClientId, model.OIDCClientSecret)

		resp, err := model.HttpClient.Do(req)
		if err != nil {
			setSessionError(session, "Token request failed")
			return
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			if err := json.Unmarshal(body, &tok); err != nil {
				setSessionError(session, "Invalid token response")
				return
			}
			break
		}

		time.Sleep(session.Interval)
	}

	// Validate access token and extract user ID
	userID, err := validateDeviceToken(tok.AccessToken)
	if err != nil {
		setSessionError(session, "Invalid access token")
		return
	}

	var aggregatorID string
	var baseURL string
	if session.AggregatorID != "" {
		aggregatorID = session.AggregatorID
		// Update existing aggregator instance with new tokens
		session.Status = StatusUpdating

		// Check if aggregator exists and user is authorized to update it
		inst, err := instance.GetAggregatorInstance(aggregatorID)
		if err != nil {
			setSessionError(session, "Aggregator not found")
			return
		}

		// Is user authorized to update this aggregator?
		if !inst.HasOwnership(userID) {
			setSessionError(session, "Not authorized to update this aggregator")
			return
		}

		baseURL = inst.BaseURL
		upsertTokens(userID, tok, model.OIDCServer, model.OIDCClientId, model.OIDCClientSecret)
		logrus.Infof("Aggregator tokens updated (device_code flow): %s", session.AggregatorID)
	} else {
		// Store tokens in central token service
		if err := upsertTokens(
			userID,
			tok,
			model.OIDCServer,
			model.OIDCClientId,
			model.OIDCClientSecret,
		); err != nil {
			setSessionError(session, "Failed to store tokens in token service")
			return
		}

		// Deploy aggregator instance
		session.Status = StatusDeploying

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		aggregatorID, err := instance.DeployAggregator(
			userID,
			session.AuthorizationServer,
			"",
			ctx,
		)
		if err != nil {
			setSessionError(session, fmt.Sprintf("Failed to deploy aggregator: %v", err))
			return
		}

		// Create aggregator record
		inst := instance.CreateAggregatorInstanceRecord(
			userID,
			"device_code",
			session.AuthorizationServer,
			aggregatorID,
		)
		baseURL = inst.BaseURL

		logrus.Infof("Aggregator created (device_code flow): %s for user %s", inst.AggregatorID, userID)
	}

	session.ResultAggregatorID = aggregatorID
	session.ResultBaseURL = baseURL
	session.ResultSubject = userID
	session.Status = StatusDone
}

// handleDeviceCodeFlowFinish checks the status of the device code flow session and responds accordingly
func handleDeviceCodeFlowFinish(w http.ResponseWriter, req model.RegistrationRequest) {
	state := req.State

	sessionsLock.Lock()
	session, ok := deviceSessions[state]
	sessionsLock.Unlock()

	if !ok {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	switch session.Status {

	case StatusPending, StatusDeploying:
		w.WriteHeader(http.StatusAccepted)
		return

	case StatusError:
		http.Error(w, session.Error, http.StatusBadRequest)
		return

	case StatusDone:
		resp := model.RegistrationResponse{
			AggregatorID: session.ResultAggregatorID,
			Aggregator:   session.ResultBaseURL,
			Subject:      session.ResultSubject,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(resp)

		// cleanup
		sessionsLock.Lock()
		delete(deviceSessions, state)
		sessionsLock.Unlock()
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
	if issStr != model.OIDCServer {
		logrus.Warnf("Token issuer mismatch: expected %s, got %s", model.OIDCServer, issStr)
		return "", errors.New("token issuer mismatch")
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

func generateState() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func setSessionError(session *DeviceSession, msg string) {
	sessionsLock.Lock()
	defer sessionsLock.Unlock()
	session.Status = StatusError
	session.Error = msg
}
