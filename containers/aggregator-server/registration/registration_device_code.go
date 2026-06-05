package registration

import (
	"aggregator/instance"
	"aggregator/model"
	"aggregator/oidc"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

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
	StatusPending   DeviceFlowStatus = "pending"
	StatusDeploying DeviceFlowStatus = "deploying"
	StatusUpdating  DeviceFlowStatus = "updating"
	StatusDone      DeviceFlowStatus = "done"
	StatusError     DeviceFlowStatus = "error"
)

// DeviceFlowType represents whether the flow is for creating a new aggregator or updating an existing one
type DeviceFlowType string

const (
	FlowCreate DeviceFlowType = "create"
	FlowUpdate DeviceFlowType = "update"
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
	Type   DeviceFlowType
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
		logrus.WithFields(logrus.Fields{
			"aggregator_id":        req.AggregatorID,
			"authorization_server": req.AuthorizationServer,
		}).Info("Routing to device code flow start")
		handleDeviceCodeFlowStart(w, req)
	} else {
		logrus.WithFields(logrus.Fields{
			"state":         req.State,
			"aggregator_id": req.AggregatorID,
		}).Info("Routing to device code flow finish")
		handleDeviceCodeFlowFinish(w, req)
	}
}

// handleDeviceCodeFlowStart initiates the device code flow by requesting a device code
// from the authorization server and returning user instructions
func handleDeviceCodeFlowStart(w http.ResponseWriter, RegReq model.RegistrationRequest) {
	log := logrus.WithFields(logrus.Fields{
		"aggregator_id":        RegReq.AggregatorID,
		"authorization_server": RegReq.AuthorizationServer,
	})
	log.Info("Starting device code flow")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get OIDC configuration
	oidcConfig, err := oidc.FetchOIDCConfig(ctx, model.OIDCServer)
	if err != nil {
		log.WithError(err).Errorf("Failed to fetch OIDC configuration for %s", model.OIDCServer)
		http.Error(w, "Authorization failed", http.StatusInternalServerError)
		return
	}
	if oidcConfig.DeviceAuthorizationEndpoint == "" {
		log.Error("OIDC config is missing device authorization endpoint")
		http.Error(w, "Authorization failed", http.StatusInternalServerError)
		return
	}
	log.WithField("device_authorization_endpoint", oidcConfig.DeviceAuthorizationEndpoint).
		Debug("Fetched OIDC configuration")

	// Determine flow type and resolve client credentials
	var aggregatorID, clientID, clientSecret string
	var flowType DeviceFlowType

	if RegReq.AggregatorID != "" {
		// Update flow — reuse existing client credentials
		aggregatorID = RegReq.AggregatorID
		flowType = FlowUpdate
		log.WithField("flow_type", flowType).Info("Detected update flow; fetching existing client credentials")

		clientID, clientSecret, err = getClientCredentials(aggregatorID)
		if err != nil {
			log.WithError(err).Errorf("Failed to retrieve client credentials for aggregator %s", aggregatorID)
			http.Error(w, "Authorization failed", http.StatusInternalServerError)
			return
		}
		log.WithField("client_id", clientID).Debug("Retrieved existing client credentials")
	} else {
		// Create flow — register a new OIDC client
		flowType = FlowCreate
		log.WithField("flow_type", flowType).Info("Detected create flow; registering new OIDC client")

		aggregatorID, clientID, clientSecret, err = registerAggregatorClient(
			ctx,
			oidcConfig,
			[]string{"urn:ietf:params:oauth:grant-type:device_code"},
		)
		if err != nil {
			log.WithError(err).Error("Failed to register new OIDC client for device code flow")
			http.Error(w, "Authorization failed", http.StatusInternalServerError)
			return
		}
		log.WithFields(logrus.Fields{
			"aggregator_id": aggregatorID,
			"client_id":     clientID,
		}).Info("Registered new OIDC client")
	}

	// Request device code from authorization server
	log.WithField("endpoint", oidcConfig.DeviceAuthorizationEndpoint).
		Debug("Requesting device code")

	data := url.Values{
		"scope": {"openid offline_access"},
	}
	CodeReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		oidcConfig.DeviceAuthorizationEndpoint,
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		log.WithError(err).Error("Failed to build device code HTTP request")
		http.Error(w, "Unable to authorize", http.StatusInternalServerError)
		return
	}
	CodeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	CodeReq.SetBasicAuth(clientID, clientSecret)

	resp, err := model.HttpClient.Do(CodeReq)
	if err != nil {
		log.WithError(err).Error("Device code request to authorization server failed")
		http.Error(w, "Unable to authorize", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.WithFields(logrus.Fields{
			"status_code": resp.StatusCode,
			"response":    string(body),
		}).Error("Authorization server returned non-2xx for device code request")
		http.Error(w, "Unable to authorize", http.StatusInternalServerError)
		return
	}

	var deviceResp DeviceCodeResponse
	if err := json.Unmarshal(body, &deviceResp); err != nil {
		log.WithError(err).WithField("response", string(body)).
			Error("Failed to parse device code response")
		http.Error(w, "Unable to authorize", http.StatusInternalServerError)
		return
	}

	log.WithFields(logrus.Fields{
		"user_code":        deviceResp.UserCode,
		"verification_uri": deviceResp.VerificationURI,
		"expires_in":       deviceResp.ExpiresIn,
		"interval":         deviceResp.Interval,
	}).Info("Received device code from authorization server")

	// Store device session metadata
	state := generateState()
	session := &DeviceSession{
		State:               state,
		AggregatorID:        aggregatorID,
		AuthorizationServer: RegReq.AuthorizationServer,
		DeviceCode:          deviceResp.DeviceCode,
		Interval:            time.Duration(deviceResp.Interval) * time.Second,
		ExpiresAt:           time.Now().Add(time.Duration(deviceResp.ExpiresIn) * time.Second),
		Status:              StatusPending,
		Type:                flowType,
	}

	sessionsLock.Lock()
	deviceSessions[state] = session
	sessionsLock.Unlock()

	log.WithFields(logrus.Fields{
		"state":         state,
		"aggregator_id": aggregatorID,
		"flow_type":     flowType,
		"expires_at":    session.ExpiresAt.UTC().Format(time.RFC3339),
	}).Info("Device session created; starting background polling")

	// Start background polling goroutine
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
		log.WithError(err).Error("Failed to write device code start response to client")
		return
	}
	log.WithField("state", state).Info("Device code flow start response sent to client")
}

// processDeviceCodeFlow continuously polls the token endpoint until the user completes
// authorization or the device code expires, then deploys or updates the aggregator.
func processDeviceCodeFlow(session *DeviceSession, oidcConfig *model.OIDCConfig) {
	log := logrus.WithFields(logrus.Fields{
		"state":         session.State,
		"aggregator_id": session.AggregatorID,
		"flow_type":     session.Type,
	})
	log.Info("Background device code polling started")

	var tok TokenResponse
	pollCount := 0

	// Extract client credentials
	clientID, clientSecret, err := getClientCredentials(session.AggregatorID)
	if err != nil {
		log.WithError(err).Error("Failed to retrieve client credentials after token grant")
		setSessionError(session, "Authorization failed")
		return
	}

	for time.Now().Before(session.ExpiresAt) {
		pollCount++
		log.WithField("poll_attempt", pollCount).Debug("Polling token endpoint")

		form := url.Values{}
		form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
		form.Set("device_code", session.DeviceCode)

		req, _ := http.NewRequest("POST", oidcConfig.TokenEndpoint, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(clientID, clientSecret)

		resp, err := model.HttpClient.Do(req)
		if err != nil {
			log.WithError(err).Error("Token poll request failed; aborting flow")
			setSessionError(session, "Token request failed")
			return
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			if err := json.Unmarshal(body, &tok); err != nil {
				log.WithError(err).WithField("response", string(body)).
					Error("Failed to parse token response")
				setSessionError(session, "Invalid token response")
				return
			}
			log.WithField("poll_attempts", pollCount).Info("Token successfully obtained")
			break
		}

		log.WithFields(logrus.Fields{
			"poll_attempt": pollCount,
			"status_code":  resp.StatusCode,
			"response":     string(body),
		}).Debug("Token not yet available; waiting before next poll")

		time.Sleep(session.Interval)
	}

	if tok.AccessToken == "" {
		log.WithFields(logrus.Fields{
			"poll_attempts": pollCount,
			"expired_at":    session.ExpiresAt.UTC().Format(time.RFC3339),
		}).Warn("Device code expired before user completed authorization")
		setSessionError(session, "Device code expired")
		return
	}

	// Validate access token and extract user ID
	userID, err := oidc.ValidateToken(tok.AccessToken, model.OIDCServer, "", clientID)
	if err != nil {
		log.WithError(err).Error("Access token validation failed")
		setSessionError(session, "Invalid access token")
		return
	}
	log.WithField("user_id", userID).Info("Access token validated")

	var baseURL string

	if session.Type == FlowUpdate {
		log.WithField("user_id", userID).Info("Updating existing aggregator tokens")
		session.Status = StatusUpdating

		inst, err := instance.GetAggregatorInstance(session.AggregatorID)
		if err != nil {
			log.WithError(err).Error("Aggregator instance not found during update flow")
			setSessionError(session, "Aggregator not found")
			return
		}

		if !inst.HasOwnership(userID) {
			log.WithFields(logrus.Fields{
				"user_id":       userID,
				"aggregator_id": session.AggregatorID,
			}).Warn("User is not authorized to update this aggregator")
			setSessionError(session, "Not authorized to update this aggregator")
			return
		}

		baseURL = inst.BaseURL
		upsertTokens(inst.AggregatorID, tok, model.OIDCServer, clientID, clientSecret)
		log.WithFields(logrus.Fields{
			"user_id":  userID,
			"base_url": baseURL,
		}).Info("Aggregator tokens updated successfully (device_code flow)")

	} else {
		log.WithField("user_id", userID).Info("Storing tokens and deploying new aggregator")

		if err := upsertTokens(session.AggregatorID, tok, model.OIDCServer, clientID, clientSecret); err != nil {
			log.WithError(err).Error("Failed to store tokens in token service")
			setSessionError(session, "Failed to store tokens in token service")
			return
		}
		log.Debug("Tokens stored in token service")

		session.Status = StatusDeploying
		log.WithField("authorization_server", session.AuthorizationServer).
			Info("Deploying aggregator instance")

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := instance.DeployAggregator(
			userID,
			session.AggregatorID,
			session.AuthorizationServer,
			ctx,
		); err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				"user_id":              userID,
				"authorization_server": session.AuthorizationServer,
			}).Error("Failed to deploy aggregator instance")
			setSessionError(session, fmt.Sprintf("Failed to deploy aggregator: %v", err))
			return
		}

		inst := instance.CreateAggregatorInstanceRecord(
			userID,
			"device_code",
			session.AuthorizationServer,
			session.AggregatorID,
		)
		baseURL = inst.BaseURL

		log.WithFields(logrus.Fields{
			"user_id":       userID,
			"aggregator_id": inst.AggregatorID,
			"base_url":      baseURL,
		}).Info("Aggregator deployed and record created (device_code flow)")
	}

	session.ResultAggregatorID = session.AggregatorID
	session.ResultBaseURL = baseURL
	session.ResultSubject = userID
	session.Status = StatusDone

	log.WithFields(logrus.Fields{
		"user_id":       userID,
		"aggregator_id": session.AggregatorID,
		"base_url":      baseURL,
		"flow_type":     session.Type,
	}).Info("Device code flow completed successfully")
}

// handleDeviceCodeFlowFinish checks the status of the device code flow session and responds accordingly
func handleDeviceCodeFlowFinish(w http.ResponseWriter, req model.RegistrationRequest) {
	state := req.State
	log := logrus.WithField("state", state)
	log.Debug("Checking device code flow session status")

	sessionsLock.Lock()
	session, ok := deviceSessions[state]
	sessionsLock.Unlock()

	if !ok {
		log.Warn("Device code flow session not found for state")
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	log.WithFields(logrus.Fields{
		"status":        session.Status,
		"aggregator_id": session.AggregatorID,
		"flow_type":     session.Type,
	}).Debug("Device code flow session status polled")

	switch session.Status {

	case StatusPending, StatusDeploying, StatusUpdating:
		log.WithField("status", session.Status).Debug("Flow still in progress; returning 202")
		w.WriteHeader(http.StatusAccepted)
		return

	case StatusError:
		log.WithFields(logrus.Fields{
			"error":         session.Error,
			"aggregator_id": session.AggregatorID,
		}).Warn("Device code flow ended in error state")
		http.Error(w, session.Error, http.StatusBadRequest)
		return

	case StatusDone:
		log.WithFields(logrus.Fields{
			"aggregator_id": session.ResultAggregatorID,
			"base_url":      session.ResultBaseURL,
			"subject":       session.ResultSubject,
		}).Info("Device code flow done; returning result and cleaning up session")

		resp := model.RegistrationResponse{
			AggregatorID: session.ResultAggregatorID,
			Aggregator:   session.ResultBaseURL,
			Subject:      session.ResultSubject,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(resp)

		sessionsLock.Lock()
		delete(deviceSessions, state)
		sessionsLock.Unlock()

		log.WithField("state", state).Debug("Device code flow session cleaned up")
	}
}

func generateState() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func setSessionError(session *DeviceSession, msg string) {
	sessionsLock.Lock()
	defer sessionsLock.Unlock()
	session.Status = StatusError
	session.Error = msg
	logrus.WithFields(logrus.Fields{
		"state":         session.State,
		"aggregator_id": session.AggregatorID,
		"flow_type":     session.Type,
		"error":         msg,
	}).Error("Device code flow session entered error state")
}
