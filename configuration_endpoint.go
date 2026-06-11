package main

import (
	"aggregator/auth"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type ConfigurationData struct {
	etagActors               int
	etagTransformations      int
	actors                   map[string]Actor
	pendingAuthorization     map[string]pendingAuthorizationCodeFlow
	availableTransformations string
	serveMux                 *http.ServeMux
	authResourcesRegistered  bool
}

var authorizeRequest = auth.AuthorizeRequest
var createAuthResource = auth.CreateResource
var deleteAuthResource = auth.DeleteResource
var redeemAuthorizationCode = redeemAuthorizationCodeAtIDP
var validateClientRedirectURI = validateRedirectURIFromClientDocument

// /config/ => read => a get to retrieve all transformations & head to get etag of transformations
// /config/actors/ => read, create => has get to retrieve all actors and their IDs, head to get etag, post to create a new actor
// /config/actors/{id} => read, delete => has get to retrieve an actor with the given ID, head to get etag, delete to delete an actor with the given ID
func startConfigurationEndpoint(mux *http.ServeMux) {
	configurationData := ConfigurationData{
		etagActors:               0,
		etagTransformations:      0,
		actors:                   make(map[string]Actor),
		pendingAuthorization:     make(map[string]pendingAuthorizationCodeFlow),
		availableTransformations: hardcodedAvailableTransformations,
		serveMux:                 mux,
	}

	configurationData.HandleFunc("/config", configurationData.HandleConfigurationEndpoint, resourceScopesRead)
	configurationData.HandleFunc("/config/actors", configurationData.HandleActorsEndpoint, resourceScopesReadCreate)
	configurationData.serveMux.HandleFunc("/registration", configurationData.HandleManagementEndpoint)
	// Catch-all handler for /config/actors/* paths (including non-existent actors)
	configurationData.HandleFunc("/config/actors/", configurationData.HandleActorEndpoint, resourceScopesReadDelete)
	configurationData.registerServerAuthResources()
}

func (data *ConfigurationData) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request), resourceScopes []auth.ResourceScope) {
	data.serveMux.HandleFunc(pattern, handler)
}

func (data *ConfigurationData) registerServerAuthResources() {
	if data.authResourcesRegistered {
		return
	}
	createAuthResource(fmt.Sprintf("%s://%s:%s/config", Protocol, Host, ServerPort), resourceScopesRead, nil)
	createAuthResource(fmt.Sprintf("%s://%s:%s/config/actors", Protocol, Host, ServerPort), resourceScopesReadCreate, nil)
	createAuthResource(fmt.Sprintf("%s://%s:%s/config/actors/", Protocol, Host, ServerPort), resourceScopesReadDelete, nil)
	RegisterAuthProxyResources()
	data.authResourcesRegistered = true
}

// setCORS adds permissive CORS headers (allow all origins)
func setCORS(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Methods", "*")
	h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	h.Set("Access-Control-Expose-Headers", "*")
}

// HandleConfigurationEndpoint handles requests to the /config endpoint
func (data *ConfigurationData) HandleConfigurationEndpoint(response http.ResponseWriter, request *http.Request) {
	setCORS(response)
	if request.Method == http.MethodOptions { // Preflight
		response.WriteHeader(http.StatusNoContent)
		return
	}
	// 1) Authorize request
	if !authorizeRequest(response, request, nil) {
		return
	}

	switch request.Method {
	case http.MethodHead:
		data.headAvailableTransformations(response, request)
	case http.MethodGet:
		data.getAvailableTransformations(response, request)
	default:
		http.Error(response, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

// headAvailableTransformations HEAD config returns ETag/header info
func (data *ConfigurationData) headAvailableTransformations(response http.ResponseWriter, _ *http.Request) {
	header := response.Header()
	header.Set("ETag", strconv.Itoa(data.etagTransformations))
	header.Set("Content-Type", "text/turtle")
}

// getAvailableTransformations GET config/transformations retrieves all available transformations
func (data *ConfigurationData) getAvailableTransformations(response http.ResponseWriter, _ *http.Request) {
	header := response.Header()
	header.Set("ETag", strconv.Itoa(data.etagTransformations))
	header.Set("Content-Type", "text/turtle")
	_, err := response.Write([]byte(data.availableTransformations))
	if err != nil {
		http.Error(response, "error when writing body", http.StatusInternalServerError)
	}
}

type managementRequest struct {
	ManagementFlow        string `json:"management_flow"`
	Aggregator            string `json:"aggregator,omitempty"`
	AuthorizationServer   string `json:"authorization_server,omitempty"`
	AuthorizationCode     string `json:"code,omitempty"`
	AuthorizationState    string `json:"state,omitempty"`
	AuthorizationRedirect string `json:"redirect_uri,omitempty"`
}

type managementResponse struct {
	Aggregator string `json:"aggregator"`
}

type authorizationCodeStartResponse struct {
	AggregatorClientID    string `json:"aggregator_client_id"`
	CodeChallenge         string `json:"code_challenge"`
	CodeChallengeMethod   string `json:"code_challenge_method"`
	State                 string `json:"state"`
	Issuer                string `json:"issuer,omitempty"`
	AuthorizationEndpoint string `json:"authorization_endpoint,omitempty"`
}

type pendingAuthorizationCodeFlow struct {
	AuthorizationServer string
	IDPClientToken      string
	IDPIssuer           string
	ApplicationClientID string
	CodeVerifier        string
	CodeChallenge       string
	State               string
	CreatedAt           time.Time
}

type oidcDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

type tokenSet struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
}

type AggregatorService struct {
	Id            string
	Performs      string
	RequestBody   string
	ResourceInput string
	OutputBody    []byte
	OutputStatus  int
	OutputHeaders map[string]string
	OutputReady   bool
	CreatedAt     time.Time
	Status        string
}

type aggregatorDiscoveryRegistration struct {
	Resources  []string `json:"resources"`
	Service    string   `json:"service"`
	Aggregator string   `json:"aggregator,omitempty"`
}

func (data *ConfigurationData) HandleManagementEndpoint(response http.ResponseWriter, request *http.Request) {
	setCORS(response)
	if request.Method == http.MethodOptions {
		response.WriteHeader(http.StatusNoContent)
		return
	}

	switch request.Method {
	case http.MethodGet:
		data.getManagedAggregators(response, request)
	case http.MethodPost:
		data.createManagedAggregator(response, request)
	case http.MethodDelete:
		data.deleteManagedAggregator(response, request)
	default:
		http.Error(response, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

func (data *ConfigurationData) getManagedAggregators(response http.ResponseWriter, request *http.Request) {
	aggregators := make([]string, 0, len(data.actors))
	for id := range data.actors {
		aggregators = append(aggregators, aggregatorURL(request, id))
	}
	writeJSON(response, request, aggregators, http.StatusOK)
}

func (data *ConfigurationData) createManagedAggregator(response http.ResponseWriter, request *http.Request) {
	if !isJSONRequest(request) {
		logrus.WithFields(logrus.Fields{"content_type": request.Header.Get("Content-Type")}).Warn("Management request rejected: unsupported media type")
		http.Error(response, "Unsupported media type", http.StatusUnsupportedMediaType)
		return
	}

	var body managementRequest
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		logrus.WithError(err).Warn("Management request rejected: malformed request body")
		http.Error(response, "Malformed request body", http.StatusBadRequest)
		return
	}
	defer request.Body.Close()

	if body.ManagementFlow == "" {
		logrus.Warn("Management request rejected: missing management_flow")
		http.Error(response, "Missing management_flow", http.StatusBadRequest)
		return
	}
	if body.ManagementFlow != "none" && body.ManagementFlow != "authorization_code" {
		logrus.WithField("management_flow", body.ManagementFlow).Warn("Management request rejected: unsupported management_flow")
		http.Error(response, "Unsupported management_flow", http.StatusBadRequest)
		return
	}
	if body.ManagementFlow == "none" && body.Aggregator != "" {
		logrus.WithField("aggregator", body.Aggregator).Warn("Management request rejected: token replacement requested for none flow")
		http.Error(response, "Token replacement is not supported for management_flow none", http.StatusBadRequest)
		return
	}

	if body.ManagementFlow == "authorization_code" {
		if body.AuthorizationCode != "" || body.AuthorizationState != "" || body.AuthorizationRedirect != "" {
			data.finishAuthorizationCodeFlow(response, request, body)
			return
		}
		data.startAuthorizationCodeFlow(response, request, body)
		return
	}
	actor := createLogicalActor()
	data.actors[actor.Id] = actor
	data.etagActors++
	data.registerAggregatorInstanceRoutes(actor)
	writeJSON(response, request, managementResponse{Aggregator: aggregatorURL(request, actor.Id)}, http.StatusCreated)
}

func (data *ConfigurationData) startAuthorizationCodeFlow(response http.ResponseWriter, request *http.Request, body managementRequest) {
	if body.AuthorizationServer == "" {
		logrus.Warn("Authorization code start rejected: missing authorization_server")
		http.Error(response, "Missing authorization_server", http.StatusBadRequest)
		return
	}
	oidcToken, ok := bearerToken(request)
	if !ok {
		logrus.Warn("Authorization code start rejected: missing OIDC bearer token")
		http.Error(response, "Missing OIDC bearer token", http.StatusUnauthorized)
		return
	}
	claims, err := managementTokenClaims(oidcToken)
	if err != nil {
		logrus.WithError(err).Warn("Authorization code start rejected: invalid OIDC bearer token")
		http.Error(response, "Invalid OIDC bearer token: "+err.Error(), http.StatusBadRequest)
		return
	}
	if claims.Issuer == "" {
		logrus.Warn("Authorization code start rejected: OIDC bearer token missing iss")
		http.Error(response, "Invalid OIDC bearer token: missing iss", http.StatusBadRequest)
		return
	}
	if claims.ApplicationClientID == "" {
		logrus.Warn("Authorization code start rejected: OIDC bearer token missing aud client identifier")
		http.Error(response, "Invalid OIDC bearer token: missing aud client identifier", http.StatusBadRequest)
		return
	}
	verifier, challenge, err := generatePKCE()
	if err != nil {
		logrus.WithError(err).Error("Failed to generate PKCE verifier")
		http.Error(response, "Failed to initialize authorization flow", http.StatusInternalServerError)
		return
	}
	state, err := randomURLSafe(32)
	if err != nil {
		logrus.WithError(err).Error("Failed to generate authorization state")
		http.Error(response, "Failed to initialize authorization flow", http.StatusInternalServerError)
		return
	}
	if data.pendingAuthorization == nil {
		data.pendingAuthorization = make(map[string]pendingAuthorizationCodeFlow)
	}
	issuer := strings.TrimSuffix(claims.Issuer, "/")
	data.pendingAuthorization[state] = pendingAuthorizationCodeFlow{
		AuthorizationServer: strings.TrimSuffix(body.AuthorizationServer, "/"),
		IDPClientToken:      oidcToken,
		IDPIssuer:           issuer,
		ApplicationClientID: claims.ApplicationClientID,
		CodeVerifier:        verifier,
		CodeChallenge:       challenge,
		State:               state,
		CreatedAt:           time.Now().UTC(),
	}
	logrus.WithFields(logrus.Fields{
		"authorization_server": body.AuthorizationServer,
		"idp_issuer":           issuer,
		"client_id":            claims.ApplicationClientID,
		"state":                state,
	}).Info("Authorization code start accepted")

	startResponse := authorizationCodeStartResponse{
		AggregatorClientID:  baseURL(request) + "/client.jsonld",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		State:               state,
	}
	writeJSON(response, request, startResponse, http.StatusCreated)
}

func (data *ConfigurationData) finishAuthorizationCodeFlow(response http.ResponseWriter, request *http.Request, body managementRequest) {
	if body.AuthorizationCode == "" {
		logrus.WithField("state", body.AuthorizationState).Warn("Authorization code finish rejected: missing code")
		http.Error(response, "Missing code", http.StatusBadRequest)
		return
	}
	if body.AuthorizationRedirect == "" {
		logrus.WithField("state", body.AuthorizationState).Warn("Authorization code finish rejected: missing redirect_uri")
		http.Error(response, "Missing redirect_uri", http.StatusBadRequest)
		return
	}
	if body.AuthorizationState == "" {
		logrus.Warn("Authorization code finish rejected: missing state")
		http.Error(response, "Missing state", http.StatusBadRequest)
		return
	}
	oidcToken, hasBearer := bearerToken(request)
	if !hasBearer {
		logrus.WithField("state", body.AuthorizationState).Warn("Authorization code finish rejected: missing OIDC bearer token")
		http.Error(response, "Missing OIDC bearer token", http.StatusUnauthorized)
		return
	}
	pending, ok := data.pendingAuthorization[body.AuthorizationState]
	if !ok {
		logrus.WithField("state", body.AuthorizationState).Warn("Authorization code finish rejected: invalid state")
		http.Error(response, "Invalid state", http.StatusBadRequest)
		return
	}
	if oidcToken != pending.IDPClientToken {
		logrus.WithField("state", body.AuthorizationState).Warn("Authorization code finish rejected: OIDC bearer token does not match pending flow")
		http.Error(response, "OIDC bearer token does not match pending authorization flow", http.StatusUnauthorized)
		return
	}
	if err := validateClientRedirectURI(pending.ApplicationClientID, body.AuthorizationRedirect); err != nil {
		logrus.WithFields(logrus.Fields{
			"state":        body.AuthorizationState,
			"client_id":    pending.ApplicationClientID,
			"redirect_uri": body.AuthorizationRedirect,
			"err":          err,
		}).Warn("Authorization code finish rejected: invalid redirect_uri")
		http.Error(response, "Invalid redirect_uri: "+err.Error(), http.StatusBadRequest)
		return
	}
	delete(data.pendingAuthorization, body.AuthorizationState)

	tokenSet, err := redeemAuthorizationCode(pending.IDPIssuer, body.AuthorizationCode, body.AuthorizationRedirect, baseURL(request)+"/client.jsonld", pending.CodeVerifier)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"state":        body.AuthorizationState,
			"idp_issuer":   pending.IDPIssuer,
			"redirect_uri": body.AuthorizationRedirect,
			"err":          err,
		}).Error("Authorization code finish failed: token redemption failed")
		http.Error(response, "Failed to redeem authorization code", http.StatusBadGateway)
		return
	}
	if tokenSet.AccessToken == "" {
		logrus.WithField("state", body.AuthorizationState).Warn("Authorization code finish failed: token endpoint response missing access_token")
		http.Error(response, "Token endpoint response missing access_token", http.StatusBadGateway)
		return
	}

	actor := createLogicalActor()
	actor.AuthorizationServer = pending.AuthorizationServer
	actor.OIDCToken = tokenSet.AccessToken
	data.actors[actor.Id] = actor
	data.etagActors++
	auth.AS_ISSUER = pending.AuthorizationServer
	data.registerServerAuthResources()
	data.registerAggregatorInstanceRoutes(actor)
	logrus.WithFields(logrus.Fields{
		"state":                body.AuthorizationState,
		"aggregator":           aggregatorURL(request, actor.Id),
		"authorization_server": pending.AuthorizationServer,
		"idp_issuer":           pending.IDPIssuer,
	}).Info("Authorization code finish accepted; aggregator created")
	writeJSON(response, request, managementResponse{Aggregator: aggregatorURL(request, actor.Id)}, http.StatusCreated)
}

func bearerToken(request *http.Request) (string, bool) {
	authorization := strings.TrimSpace(request.Header.Get("Authorization"))
	if len(authorization) <= len("Bearer ") || !strings.EqualFold(authorization[:len("Bearer ")], "Bearer ") {
		return "", false
	}
	token := strings.TrimSpace(authorization[len("Bearer "):])
	return token, token != ""
}

func generatePKCE() (string, string, error) {
	verifier, err := randomURLSafe(32)
	if err != nil {
		return "", "", err
	}
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])
	return verifier, challenge, nil
}

func randomURLSafe(size int) (string, error) {
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

type managementTokenMetadata struct {
	Issuer              string
	ApplicationClientID string
}

func managementTokenClaims(token string) (managementTokenMetadata, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return managementTokenMetadata{}, fmt.Errorf("invalid JWT format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		if payload, err = base64.URLEncoding.DecodeString(parts[1]); err != nil {
			return managementTokenMetadata{}, fmt.Errorf("invalid JWT payload: %w", err)
		}
	}
	var claims struct {
		Issuer   string          `json:"iss"`
		Audience json.RawMessage `json:"aud"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return managementTokenMetadata{}, fmt.Errorf("invalid JWT payload JSON: %w", err)
	}
	clientID, err := clientIDFromAudience(claims.Audience)
	if err != nil {
		return managementTokenMetadata{}, err
	}
	return managementTokenMetadata{Issuer: claims.Issuer, ApplicationClientID: clientID}, nil
}

func clientIDFromAudience(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}
	var audience string
	if err := json.Unmarshal(raw, &audience); err == nil {
		if strings.HasPrefix(audience, "http://") || strings.HasPrefix(audience, "https://") {
			return audience, nil
		}
		return "", fmt.Errorf("aud is not a dereferenceable client identifier")
	}
	var audiences []string
	if err := json.Unmarshal(raw, &audiences); err != nil {
		return "", fmt.Errorf("invalid aud claim")
	}
	for _, audience := range audiences {
		if strings.HasPrefix(audience, "http://") || strings.HasPrefix(audience, "https://") {
			return audience, nil
		}
	}
	return "", fmt.Errorf("aud does not contain a dereferenceable client identifier")
}

func validateRedirectURIFromClientDocument(clientID, redirectURI string) error {
	response, err := http.Get(clientID)
	if err != nil {
		return fmt.Errorf("failed to dereference client_id %q: %w", clientID, err)
	}
	defer response.Body.Close()
	if response.StatusCode >= 400 {
		return fmt.Errorf("client_id %q returned %s", clientID, response.Status)
	}
	var document struct {
		RedirectURIs []string `json:"redirect_uris"`
	}
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		return fmt.Errorf("failed to parse client_id document: %w", err)
	}
	for _, registered := range document.RedirectURIs {
		if registered == redirectURI {
			return nil
		}
	}
	return fmt.Errorf("redirect_uri is not registered in client_id document")
}

func fetchOIDCDiscovery(issuer string) (oidcDiscovery, error) {
	response, err := http.Get(strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration")
	if err != nil {
		return oidcDiscovery{}, err
	}
	defer response.Body.Close()
	if response.StatusCode >= 400 {
		return oidcDiscovery{}, fmt.Errorf("OIDC discovery returned %s", response.Status)
	}
	var metadata oidcDiscovery
	if err := json.NewDecoder(response.Body).Decode(&metadata); err != nil {
		return oidcDiscovery{}, err
	}
	return metadata, nil
}

func redeemAuthorizationCodeAtIDP(issuer, code, redirectURI, clientID, codeVerifier string) (tokenSet, error) {
	metadata, err := fetchOIDCDiscovery(issuer)
	if err != nil {
		return tokenSet{}, err
	}
	if metadata.TokenEndpoint == "" {
		return tokenSet{}, fmt.Errorf("OIDC discovery missing token_endpoint")
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", clientID)
	form.Set("code_verifier", codeVerifier)

	request, err := http.NewRequest(http.MethodPost, metadata.TokenEndpoint, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return tokenSet{}, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return tokenSet{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(response.Body)
		return tokenSet{}, fmt.Errorf("token endpoint returned %s: %s", response.Status, string(body))
	}
	var tokens tokenSet
	if err := json.NewDecoder(response.Body).Decode(&tokens); err != nil {
		return tokenSet{}, err
	}
	return tokens, nil
}

func (data *ConfigurationData) deleteManagedAggregator(response http.ResponseWriter, request *http.Request) {
	if !isJSONRequest(request) {
		http.Error(response, "Unsupported media type", http.StatusUnsupportedMediaType)
		return
	}

	var body managementRequest
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		http.Error(response, "Malformed request body", http.StatusBadRequest)
		return
	}
	defer request.Body.Close()

	if body.Aggregator == "" {
		http.Error(response, "Missing aggregator", http.StatusBadRequest)
		return
	}
	id, err := actorIDFromAggregatorURL(body.Aggregator)
	if err != nil {
		http.Error(response, "Invalid aggregator", http.StatusBadRequest)
		return
	}
	actor, ok := data.actors[id]
	if !ok {
		http.Error(response, "Aggregator not found", http.StatusNotFound)
		return
	}

	actor.Stop()
	data.deleteAggregatorAuthResources(request, actor)
	delete(data.actors, id)
	data.etagActors++
	response.WriteHeader(http.StatusNoContent)
}

func (data *ConfigurationData) deleteAggregatorAuthResources(request *http.Request, actor Actor) {
	if actor.AuthorizationServer == "" {
		return
	}
	oldIssuer := auth.AS_ISSUER
	auth.AS_ISSUER = actor.AuthorizationServer
	defer func() {
		auth.AS_ISSUER = oldIssuer
	}()

	base := aggregatorURL(request, actor.Id)
	for _, service := range actor.Services {
		serviceURL := base + "services/" + service.Id + "/"
		deleteAuthResource(serviceURL)
		deleteAuthResource(strings.TrimSuffix(serviceURL, "/"))
		deleteAuthResource(serviceURL + "output")
	}
	deleteAuthResource(base)
	deleteAuthResource(strings.TrimSuffix(base, "/"))
	deleteAuthResource(base + "transformations")
	deleteAuthResource(base + "services")
}

func isJSONRequest(request *http.Request) bool {
	contentType := request.Header.Get("Content-Type")
	if contentType == "" {
		return false
	}
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	return mediaType == "application/json"
}

func aggregatorURL(request *http.Request, actorID string) string {
	return baseURL(request) + "/" + actorID + "/"
}

func actorIDFromAggregatorURL(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		return "", fmt.Errorf("missing actor id")
	}
	return parts[0], nil
}

type aggregatorDescriptionContext struct {
	ID                        string   `json:"id"`
	Aggr                      string   `json:"aggr"`
	Xsd                       string   `json:"xsd"`
	CreatedAt                 jsonLDID `json:"created_at"`
	LoginStatus               jsonLDID `json:"login_status"`
	TokenExpiry               jsonLDID `json:"token_expiry"`
	TransformationCatalog     jsonLDID `json:"transformation_catalog"`
	ServiceCollectionEndpoint jsonLDID `json:"service_collection_endpoint"`
}

type aggregatorDescription struct {
	Context                   aggregatorDescriptionContext `json:"@context"`
	ID                        string                       `json:"id"`
	Type                      string                       `json:"@type"`
	CreatedAt                 string                       `json:"created_at"`
	LoginStatus               bool                         `json:"login_status"`
	TokenExpiry               string                       `json:"token_expiry,omitempty"`
	TransformationCatalog     string                       `json:"transformation_catalog"`
	ServiceCollectionEndpoint string                       `json:"service_collection_endpoint"`
}

func (data *ConfigurationData) registerAggregatorInstanceRoutes(actor Actor) {
	actorID := actor.Id
	basePath := "/" + actorID
	data.serveMux.HandleFunc(basePath, data.HandleAggregatorInstanceEndpoint)
	data.serveMux.HandleFunc(basePath+"/", data.HandleAggregatorInstanceEndpoint)

	if actor.AuthorizationServer == "" {
		return
	}
	base := fmt.Sprintf("%s://%s:%s%s", Protocol, Host, ServerPort, basePath)
	createAuthResource(base+"/", resourceScopesRead, nil)
	createAuthResource(base+"/transformations", resourceScopesRead, nil)
	createAuthResource(base+"/services", resourceScopesReadCreate, nil)
}

func (data *ConfigurationData) HandleAggregatorInstanceEndpoint(response http.ResponseWriter, request *http.Request) {
	setCORS(response)
	if request.Method == http.MethodOptions {
		response.WriteHeader(http.StatusNoContent)
		return
	}
	actorID, relPath, err := extractActorAndPath(request.URL.Path)
	if err != nil {
		http.Error(response, "Invalid aggregator path", http.StatusBadRequest)
		return
	}
	actor, ok := data.actors[actorID]
	if !ok {
		http.Error(response, "Aggregator not found", http.StatusNotFound)
		return
	}

	if actor.AuthorizationServer != "" && !authorizeRequest(response, request, nil) {
		return
	}

	normalizedPath := normalizeRelativePath(relPath)
	if normalizedPath != "/" {
		normalizedPath = strings.TrimSuffix(normalizedPath, "/")
	}

	switch normalizedPath {
	case "/":
		data.getAggregatorDescription(response, request, actor)
	case "/transformations":
		data.getInstanceTransformationCatalog(response, request, actor)
	case "/services":
		data.handleServiceCollection(response, request, actor)
	default:
		if strings.HasPrefix(normalizedPath, "/services/") {
			data.handleServiceEndpoint(response, request, actor, normalizedPath)
			return
		}
		http.NotFound(response, request)
	}
}

func (data *ConfigurationData) getAggregatorDescription(response http.ResponseWriter, request *http.Request, actor Actor) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		http.Error(response, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	createdAt := actor.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	id := aggregatorURL(request, actor.Id)
	description := aggregatorDescription{
		Context: aggregatorDescriptionContext{
			ID:   "@id",
			Aggr: "https://w3id.org/aggregator#",
			Xsd:  "http://www.w3.org/2001/XMLSchema#",
			CreatedAt: jsonLDID{
				ID:   "aggr:createdAt",
				Type: "xsd:dateTime",
			},
			LoginStatus: jsonLDID{
				ID:   "aggr:loginStatus",
				Type: "xsd:boolean",
			},
			TokenExpiry: jsonLDID{
				ID:   "aggr:tokenExpiry",
				Type: "xsd:dateTime",
			},
			TransformationCatalog: jsonLDID{
				ID:   "aggr:transformationsEndpoint",
				Type: "@id",
			},
			ServiceCollectionEndpoint: jsonLDID{
				ID:   "aggr:serviceCollectionEndpoint",
				Type: "@id",
			},
		},
		ID:                        id,
		Type:                      "aggr:Aggregator",
		CreatedAt:                 createdAt.UTC().Format(time.RFC3339),
		LoginStatus:               true,
		TransformationCatalog:     id + "transformations",
		ServiceCollectionEndpoint: id + "services",
	}
	writeJSON(response, request, description, http.StatusOK)
}

func (data *ConfigurationData) getInstanceTransformationCatalog(response http.ResponseWriter, request *http.Request, actor Actor) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		http.Error(response, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	response.Header().Set("ETag", generateActorETag(fmt.Sprintf("%s:transformations:%d", actor.Id, actor.etagServices)))
	response.Header().Set("Content-Type", "text/turtle")
	if request.Method == http.MethodHead {
		return
	}

	serviceTransformations := ""
	for _, service := range actor.Services {
		serviceURL := aggregatorURL(request, actor.Id) + "services/" + service.Id + "/"
		serviceTransformations += fmt.Sprintf(`
<%s#transformation>
    a aggr:Transformation ;
    aggr:implementedBy <%s> ;
    aggr:performs <%s> .
`, serviceURL, serviceURL, service.Performs)
	}

	hasServiceTransformations := ""
	if serviceTransformations != "" {
		hasServiceTransformations = "\n" + serviceTransformations
	}

	body := fmt.Sprintf(`@base <%stransformations#> .
@prefix aggr: <https://w3id.org/aggregator#> .

<> a aggr:TransformationCatalog .
%s`, aggregatorURL(request, actor.Id), hasServiceTransformations)
	_, _ = response.Write([]byte(body))
}

func (data *ConfigurationData) handleServiceCollection(response http.ResponseWriter, request *http.Request, actor Actor) {
	response.Header().Set("Accept-Post", "text/turtle")
	if request.Method == http.MethodPost {
		data.deployService(response, request, actor)
		return
	}
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		http.Error(response, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	etag := generateActorETag(fmt.Sprintf("%s:%d", actor.Id, actor.etagServices))
	response.Header().Set("ETag", etag)
	response.Header().Set("Content-Type", "text/turtle")
	if request.Method == http.MethodHead {
		return
	}

	collectionURL := aggregatorURL(request, actor.Id) + "services"
	serviceURLs := []string{}
	for serviceID := range actor.Services {
		serviceURLs = append(serviceURLs, fmt.Sprintf("<%sservices/%s/>", aggregatorURL(request, actor.Id), serviceID))
	}
	sort.Strings(serviceURLs)
	serviceTriples := ""
	if len(serviceURLs) == 0 {
		serviceTriples = fmt.Sprintf("<%s>\n    a aggr:ServiceCollection .\n", collectionURL)
	} else {
		serviceTriples = fmt.Sprintf("<%s>\n    a aggr:ServiceCollection ;\n    aggr:hasService %s .\n", collectionURL, strings.Join(serviceURLs, ",\n        "))
	}

	body := fmt.Sprintf(`@base <%sservices#> .
@prefix aggr: <https://w3id.org/aggregator#> .

%s`, aggregatorURL(request, actor.Id), serviceTriples)
	_, _ = response.Write([]byte(body))
}

func (data *ConfigurationData) deployService(response http.ResponseWriter, request *http.Request, actor Actor) {
	if !isTurtleRequest(request) {
		http.Error(response, "Unsupported media type", http.StatusUnsupportedMediaType)
		return
	}

	bodyBytes, err := io.ReadAll(request.Body)
	if err != nil {
		http.Error(response, "Invalid request payload", http.StatusBadRequest)
		return
	}
	defer request.Body.Close()

	requestBody := string(bodyBytes)
	performs, err := extractPerforms(requestBody)
	if err != nil {
		http.Error(response, err.Error(), http.StatusBadRequest)
		return
	}
	resourceInput := ""
	if isCopyResourceTransformation(performs) {
		resourceInput, err = extractResourceLocation(requestBody)
		if err != nil {
			http.Error(response, err.Error(), http.StatusBadRequest)
			return
		}
	}

	serviceID := uuid.NewString()
	service := AggregatorService{
		Id:            serviceID,
		Performs:      performs,
		RequestBody:   requestBody,
		ResourceInput: resourceInput,
		OutputHeaders: make(map[string]string),
		CreatedAt:     time.Now().UTC(),
		Status:        "created",
	}
	if isCopyResourceTransformation(performs) {
		service.Status = "starting"
	}
	if actor.Services == nil {
		actor.Services = make(map[string]AggregatorService)
	}
	actor.Services[serviceID] = service
	actor.etagServices++
	data.actors[actor.Id] = actor
	if isCopyResourceTransformation(performs) {
		go data.retryCopyResourceOutput(actor.Id, service.Id)
	}

	serviceURL := aggregatorURL(request, actor.Id) + "services/" + serviceID + "/"
	if actor.AuthorizationServer != "" {
		createAuthResource(serviceURL, resourceScopesReadDelete, nil)
		createAuthResource(strings.TrimSuffix(serviceURL, "/"), resourceScopesReadDelete, nil)
		createAuthResource(serviceURL+"output", resourceScopesRead, nil)
	}
	data.registerAggregatorDiscovery(actor.Id, serviceURL, requestBody)

	response.Header().Set("Location", serviceURL)
	response.Header().Set("Content-Type", "text/turtle")
	response.WriteHeader(http.StatusCreated)
	_, _ = response.Write([]byte(renderServiceDescription(request, actor, service)))
}

func isTurtleRequest(request *http.Request) bool {
	contentType := request.Header.Get("Content-Type")
	if contentType == "" {
		return false
	}
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	return mediaType == "text/turtle" || mediaType == "application/n-triples" || mediaType == "application/ld+json"
}

func extractPerforms(body string) (string, error) {
	if !strings.Contains(body, "aggr:Service") && !strings.Contains(body, "<https://w3id.org/aggregator#Service>") {
		return "", fmt.Errorf("request must describe exactly one aggr:Service")
	}
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`aggr:performs\s+<([^>]+)>`),
		regexp.MustCompile(`<https://w3id\.org/aggregator#performs>\s+<([^>]+)>`),
	}
	for _, pattern := range patterns {
		matches := pattern.FindStringSubmatch(body)
		if len(matches) == 2 {
			return matches[1], nil
		}
	}
	return "", fmt.Errorf("request must include aggr:performs")
}

func isCopyResourceTransformation(performs string) bool {
	return strings.HasSuffix(performs, "#CopyResource") || strings.HasSuffix(performs, "/CopyResource") || performs == "CopyResource"
}

func extractResourceLocation(body string) (string, error) {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?s)fnoc:boundParameter\s+<[^>]*(?:#|/)ResourceLocation>\s*;\s*fnoc:boundToTerm\s+<([^>]+)>`),
		regexp.MustCompile(`(?s)fnoc:boundParameter\s+<[^>]*(?:#|/)ResourceLocation>\s*;\s*fnoc:boundToTerm\s+"([^"]+)"`),
		regexp.MustCompile(`(?s)<https://w3id\.org/function/vocabulary/composition#boundParameter>\s+<[^>]*(?:#|/)ResourceLocation>\s*;\s*<https://w3id\.org/function/vocabulary/composition#boundToTerm>\s+<([^>]+)>`),
		regexp.MustCompile(`(?s)<https://w3id\.org/function/vocabulary/composition#boundParameter>\s+<[^>]*(?:#|/)ResourceLocation>\s*;\s*<https://w3id\.org/function/vocabulary/composition#boundToTerm>\s+"([^"]+)"`),
		regexp.MustCompile(`<resourceLocation>\s+<([^>]+)>`),
		regexp.MustCompile(`<resourceLocation>\s+"([^"]+)"`),
		regexp.MustCompile(`copy:resourceLocation\s+<([^>]+)>`),
		regexp.MustCompile(`copy:resourceLocation\s+"([^"]+)"`),
	}
	for _, pattern := range patterns {
		matches := pattern.FindStringSubmatch(body)
		if len(matches) == 2 && strings.TrimSpace(matches[1]) != "" {
			return strings.TrimSpace(matches[1]), nil
		}
	}
	return "", fmt.Errorf("CopyResource service must bind ResourceLocation using aggr:applies/fnoc:parameterBindings")
}

func extractSourceResources(body string) []string {
	resources := make(map[string]bool)

	sourceListPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?s)trans:sources\s*\((.*?)\)`),
		regexp.MustCompile(`(?s)trans:discoverySources\s*\((.*?)\)`),
		regexp.MustCompile(`(?s)<http://localhost:5000/config/transformations#sources>\s*\((.*?)\)`),
		regexp.MustCompile(`(?s)<http://localhost:5000/config/transformations#discoverySources>\s*\((.*?)\)`),
		regexp.MustCompile(`(?s)<[^>]*(?:#|/)sources>\s*\((.*?)\)`),
		regexp.MustCompile(`(?s)<[^>]*(?:#|/)discoverySources>\s*\((.*?)\)`),
	}
	for _, pattern := range sourceListPatterns {
		for _, match := range pattern.FindAllStringSubmatch(body, -1) {
			if len(match) != 2 {
				continue
			}
			for _, resource := range extractURLsFromText(match[1]) {
				resources[resource] = true
			}
		}
	}

	if resourceInput, err := extractResourceLocation(body); err == nil {
		resources[resourceInput] = true
	}

	result := make([]string, 0, len(resources))
	for resource := range resources {
		if normalized, ok := normalizeDiscoveryResource(resource); ok {
			result = append(result, normalized)
		}
	}
	sort.Strings(result)
	return result
}

func extractURLsFromText(input string) []string {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`<([^>]+)>`),
		regexp.MustCompile(`"([^"]+)"(?:\^\^xsd:string|\^\^<http://www\.w3\.org/2001/XMLSchema#string>)?`),
	}
	urls := []string{}
	for _, pattern := range patterns {
		for _, match := range pattern.FindAllStringSubmatch(input, -1) {
			if len(match) == 2 {
				urls = append(urls, match[1])
			}
		}
	}
	return urls
}

func normalizeDiscoveryResource(raw string) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", false
	}
	if parsed.Host == Host+":"+ServerPort || strings.HasPrefix(parsed.Host, "localhost:5000") {
		return "", false
	}
	parsed.Fragment = ""
	return parsed.String(), true
}

func (data *ConfigurationData) registerAggregatorDiscovery(actorID string, serviceURL string, serviceDescription string) {
	resources := extractSourceResources(serviceDescription)
	if len(resources) == 0 {
		return
	}

	resourcesByOrigin := make(map[string][]string)
	for _, resource := range resources {
		parsed, err := url.Parse(resource)
		if err != nil {
			continue
		}
		origin := parsed.Scheme + "://" + parsed.Host
		resourcesByOrigin[origin] = append(resourcesByOrigin[origin], resource)
	}

	for origin, originResources := range resourcesByOrigin {
		registration := aggregatorDiscoveryRegistration{
			Resources:  originResources,
			Service:    serviceURL,
			Aggregator: fmt.Sprintf("%s://%s:%s/%s/", Protocol, Host, ServerPort, actorID),
		}
		body, err := json.Marshal(registration)
		if err != nil {
			logrus.WithError(err).Warn("Failed to encode aggregator discovery registration")
			continue
		}
		endpoint := strings.TrimSuffix(origin, "/") + "/.well-known/aggregator-discovery"
		request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			logrus.WithFields(logrus.Fields{"endpoint": endpoint, "err": err}).Warn("Failed to create aggregator discovery request")
			continue
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			logrus.WithFields(logrus.Fields{"endpoint": endpoint, "err": err}).Warn("Failed to register aggregator discovery")
			continue
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			logrus.WithFields(logrus.Fields{
				"endpoint": endpoint,
				"status":   response.Status,
			}).Warn("Aggregator discovery registration was rejected")
			continue
		}
		logrus.WithFields(logrus.Fields{
			"endpoint":  endpoint,
			"resources": len(originResources),
			"service":   serviceURL,
		}).Info("Registered aggregator discovery")
	}
}

func (data *ConfigurationData) handleServiceEndpoint(response http.ResponseWriter, request *http.Request, actor Actor, normalizedPath string) {
	pathParts := strings.Split(strings.Trim(normalizedPath, "/"), "/")
	if len(pathParts) < 2 || pathParts[0] != "services" {
		http.NotFound(response, request)
		return
	}
	serviceID := pathParts[1]
	service, ok := actor.Services[serviceID]
	if !ok {
		http.Error(response, "Service not found", http.StatusNotFound)
		return
	}

	if len(pathParts) == 3 && pathParts[2] == "output" {
		data.handleServiceOutput(response, request, actor, service)
		return
	}
	if len(pathParts) != 2 {
		http.NotFound(response, request)
		return
	}

	switch request.Method {
	case http.MethodGet, http.MethodHead:
		response.Header().Set("Content-Type", "text/turtle")
		if request.Method == http.MethodHead {
			return
		}
		_, _ = response.Write([]byte(renderServiceDescription(request, actor, service)))
	case http.MethodDelete:
		delete(actor.Services, service.Id)
		actor.etagServices++
		data.actors[actor.Id] = actor
		deleteAuthResource(aggregatorURL(request, actor.Id) + "services/" + service.Id + "/")
		deleteAuthResource(aggregatorURL(request, actor.Id) + "services/" + service.Id)
		deleteAuthResource(aggregatorURL(request, actor.Id) + "services/" + service.Id + "/output")
		response.WriteHeader(http.StatusNoContent)
	default:
		http.Error(response, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

func (data *ConfigurationData) handleServiceOutput(response http.ResponseWriter, request *http.Request, actor Actor, service AggregatorService) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		http.Error(response, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	serviceURL := aggregatorURL(request, actor.Id) + "services/" + service.Id + "/"
	response.Header().Set("Link", fmt.Sprintf("<%s>; rel=\"https://w3id.org/aggregator#fromService\"", serviceURL))
	if isCopyResourceTransformation(service.Performs) {
		data.handleCopyResourceOutput(response, request, service)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (data *ConfigurationData) handleCopyResourceOutput(response http.ResponseWriter, request *http.Request, service AggregatorService) {
	if service.ResourceInput == "" {
		http.Error(response, "CopyResource service is missing resource input", http.StatusInternalServerError)
		return
	}
	if !service.OutputReady {
		response.Header().Set("Retry-After", "1")
		response.Header().Set("Content-Type", "text/plain; charset=utf-8")
		response.WriteHeader(http.StatusServiceUnavailable)
		if request.Method != http.MethodHead {
			_, _ = response.Write([]byte("Service output is not ready yet; retry later.\n"))
		}
		return
	}
	for key, value := range service.OutputHeaders {
		if value != "" {
			response.Header().Set(key, value)
		}
	}
	status := service.OutputStatus
	if status == 0 {
		status = http.StatusOK
	}
	response.WriteHeader(status)
	if request.Method == http.MethodHead {
		return
	}
	if _, err := response.Write(service.OutputBody); err != nil {
		logrus.WithFields(logrus.Fields{"resource": service.ResourceInput, "err": err}).Warn("Failed to write CopyResource cached output")
	}
}

func (data *ConfigurationData) fetchAndCacheCopyResourceOutput(service *AggregatorService) {
	upstreamResponse, err := http.Get(service.ResourceInput)
	if err != nil {
		logrus.WithFields(logrus.Fields{"resource": service.ResourceInput, "err": err}).Warn("CopyResource input is not ready")
		service.Status = "starting"
		service.OutputReady = false
		return
	}
	defer upstreamResponse.Body.Close()

	body, err := io.ReadAll(upstreamResponse.Body)
	if err != nil {
		logrus.WithFields(logrus.Fields{"resource": service.ResourceInput, "err": err}).Warn("Failed to cache CopyResource input")
		service.Status = "error"
		service.OutputReady = false
		return
	}
	service.OutputBody = body
	service.OutputStatus = upstreamResponse.StatusCode
	service.OutputHeaders = map[string]string{
		"Content-Type":  upstreamResponse.Header.Get("Content-Type"),
		"ETag":          upstreamResponse.Header.Get("ETag"),
		"Last-Modified": upstreamResponse.Header.Get("Last-Modified"),
	}
	service.OutputReady = true
	if upstreamResponse.StatusCode >= 200 && upstreamResponse.StatusCode < 300 {
		service.Status = "created"
	} else {
		service.Status = "error"
	}
}

func (data *ConfigurationData) retryCopyResourceOutput(actorID string, serviceID string) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for attempts := 0; attempts < 60; attempts++ {
		actor, ok := data.actors[actorID]
		if !ok {
			return
		}
		service, ok := actor.Services[serviceID]
		if !ok || service.OutputReady {
			return
		}

		data.fetchAndCacheCopyResourceOutput(&service)
		actor.Services[serviceID] = service
		data.actors[actorID] = actor
		if service.OutputReady {
			return
		}
		<-ticker.C
	}
}

func renderServiceDescription(request *http.Request, actor Actor, service AggregatorService) string {
	serviceURL := aggregatorURL(request, actor.Id) + "services/" + service.Id + "/"
	datasetURL := serviceURL + "#dataset"
	distributionURL := serviceURL + "#distribution"
	outputURL := serviceURL + "output"
	return fmt.Sprintf(`@prefix aggr: <https://w3id.org/aggregator#> .
@prefix dcat: <http://www.w3.org/ns/dcat#> .
@prefix dct: <http://purl.org/dc/terms/> .
@prefix prov: <http://www.w3.org/ns/prov#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .

<%s>
    a aggr:Service ;
    a dcat:DataService ;
    a prov:SoftwareAgent ;
    aggr:status %q ;
    aggr:createdAt %q^^xsd:dateTime ;
    aggr:performs <%s> ;
    %s
    dct:conformsTo <https://w3id.org/aggregator#> ;
    dcat:servesDataset <%s> .

<%s>
    a dcat:Dataset ;
    aggr:forOutput <http://localhost:5000/transformations#Result> ;
    dcat:distribution <%s> .

<%s>
    a dcat:Distribution ;
    dcat:accessURL <%s> ;
    dcat:accessService <%s> .
`, serviceURL, service.Status, service.CreatedAt.UTC().Format(time.RFC3339), service.Performs, renderServiceInputTriple(service), datasetURL, datasetURL, distributionURL, distributionURL, outputURL, serviceURL)
}

func renderServiceInputTriple(service AggregatorService) string {
	if service.ResourceInput == "" {
		return ""
	}
	return fmt.Sprintf("    <resourceLocation> <%s> ;", service.ResourceInput)
}

// HandleActorsEndpoint handles requests to the /config/actors endpoint
func (data *ConfigurationData) HandleActorsEndpoint(response http.ResponseWriter, request *http.Request) {
	setCORS(response)
	if request.Method == http.MethodOptions { // Preflight
		response.WriteHeader(http.StatusNoContent)
		return
	}
	// 1) Authorize request
	if !authorizeRequest(response, request, nil) {
		return
	}

	if request.URL.Path == "/config/actors" {
		switch request.Method {
		case http.MethodHead:
			data.headActors(response, request)
		case http.MethodGet:
			data.getActors(response, request)
		case http.MethodPost:
			data.createActor(response, request)
		default:
			http.Error(response, "Invalid request method", http.StatusMethodNotAllowed)
		}
		return
	}
}

// headActors HEAD returns ETag header for actors collection
func (data *ConfigurationData) headActors(response http.ResponseWriter, _ *http.Request) {
	header := response.Header()
	header.Set("Content-Type", "application/json")
	header.Set("ETag", strconv.Itoa(data.etagActors))
	response.WriteHeader(http.StatusOK)
}

// getActors GET config retrieves all actors and their IDs
func (data *ConfigurationData) getActors(response http.ResponseWriter, _ *http.Request) {
	header := response.Header()
	header.Set("Content-Type", "application/json")
	header.Set("ETag", strconv.Itoa(data.etagActors))
	actors := "{\"actors\":["
	ids := []string{}
	for _, actor := range data.actors {
		ids = append(ids, "\""+actor.Id+"\"")
	}
	actors += strings.Join(ids, ",")
	actors += "]}"
	_, err := response.Write([]byte(actors))
	if err != nil {
		http.Error(response, "error when writing body", http.StatusInternalServerError)
	}
}

// createActor creates a new actor
func (data *ConfigurationData) createActor(response http.ResponseWriter, request *http.Request) {
	pipelineDescription, err := io.ReadAll(request.Body)
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("Failed to read pipeline description")
		http.Error(response, "Invalid request payload", http.StatusBadRequest)
		return
	}
	defer request.Body.Close()
	logrus.WithFields(logrus.Fields{"pipeline_description": string(pipelineDescription)}).Debug("Transformation received")

	var actor Actor
	if request.URL.Query().Get("descriptionOnly") == "true" {
		actor = createLogicalActor()
		actor.PipelineDescription = string(pipelineDescription)
	} else {
		actor, err = createActor(string(pipelineDescription))
		if err != nil {
			logrus.WithFields(logrus.Fields{"err": err}).Error("Failed to create an actor")
			http.Error(response, "Failed to create the actor", http.StatusInternalServerError)
			return
		}
	}

	data.actors[actor.Id] = actor
	data.etagActors++

	err = auth.CreateResource(
		fmt.Sprintf("%s://%s:%s%s", Protocol, Host, ServerPort, fmt.Sprintf("/config/actors/%s", actor.Id)),
		resourceScopesReadDelete,
		nil,
	)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"err":      err,
			"resource": fmt.Sprintf("%s://%s:%s%s", Protocol, Host, ServerPort, fmt.Sprintf("/config/actors/%s", actor.Id)),
		}).Info("Failed to create resource for actor config endpoint")
		return
	}
	header := response.Header()
	header.Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusCreated)
	_, err = response.Write([]byte(actor.marshalActor()))
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("Error writing create actor response")
		return
	}
	data.registerAggregatorDiscovery(actor.Id, fmt.Sprintf("%s://%s:%s/config/actors/%s", Protocol, Host, ServerPort, actor.Id), string(pipelineDescription))
}

// HandleActorEndpoint handles requests to the /config/actors/{id} endpoint
func (data *ConfigurationData) HandleActorEndpoint(response http.ResponseWriter, request *http.Request) {
	setCORS(response)
	if request.Method == http.MethodOptions {
		response.WriteHeader(http.StatusNoContent)
		return
	}
	parts := strings.Split(request.URL.Path, "/")
	if len(parts) < 4 || parts[3] == "" {
		http.Error(response, "Invalid request path", http.StatusBadRequest)
		return
	}
	actor, ok := data.actors[parts[3]]
	if !ok {
		http.Error(response, "Actor with id "+parts[3]+" not found", http.StatusNotFound)
		return
	}

	if !authorizeRequest(response, request, nil) {
		return
	}

	switch request.Method {
	case http.MethodHead:
		data.headActor(response, request, actor)
	case http.MethodGet:
		data.getActor(response, request, actor)
	case http.MethodDelete:
		data.deleteActor(response, request, actor)
	default:
		http.Error(response, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

// generateActorETag generates a consistent ETag based on the marshaled actor data
func generateActorETag(marshaledData string) string {
	hash := sha256.Sum256([]byte(marshaledData))
	return hex.EncodeToString(hash[:8]) // Use first 8 bytes for a shorter ETag
}

// headActor HEAD config/actors/{id} returns the ETag header for the actor with the given ID
func (data *ConfigurationData) headActor(response http.ResponseWriter, request *http.Request, actor Actor) {
	logrus.WithFields(logrus.Fields{"actor_id": actor.Id}).Debug("Request head for actor")
	header := response.Header()
	header.Set("Content-Type", "application/json")
	header.Set("ETag", generateActorETag(actor.marshalActor()))
	response.WriteHeader(http.StatusOK)
}

func (data *ConfigurationData) getActor(response http.ResponseWriter, request *http.Request, actor Actor) {
	logrus.WithFields(logrus.Fields{"actor_id": actor.Id}).Info("Request get for actor")
	marshaledData := actor.marshalActor()
	header := response.Header()
	header.Set("Content-Type", "application/json")
	header.Set("ETag", generateActorETag(marshaledData))
	_, err := response.Write([]byte(marshaledData))
	if err != nil {
		http.Error(response, "error when writing body", http.StatusInternalServerError)
	}
}

// deleteActor DELETE config/actors/{id} deletes an actor with the given ID
func (data *ConfigurationData) deleteActor(response http.ResponseWriter, _ *http.Request, actor Actor) {
	logrus.WithFields(logrus.Fields{"actor_id": actor.Id}).Info("Request to delete transformation")
	actor.Stop()
	delete(data.actors, actor.Id)
	data.etagActors++
	response.WriteHeader(http.StatusOK)

	deleteAuthResource(
		fmt.Sprintf("%s://%s:%s/config/actors/%s", Protocol, Host, ServerPort, actor.Id),
	)
}

// Replace resourceScopes* slices with enum slices using auth.ResourceScope
var resourceScopesRead = []auth.ResourceScope{auth.ScopeRead}
var resourceScopesReadDelete = []auth.ResourceScope{auth.ScopeRead, auth.ScopeDelete}
var resourceScopesReadCreate = []auth.ResourceScope{auth.ScopeRead, auth.ScopeCreate}

const hardcodedAvailableTransformations = `
@base <http://localhost:5000/transformations#> .
@prefix aggr: <https://w3id.org/aggregator#> .
@prefix dcat: <http://www.w3.org/ns/dcat#> .
@prefix dct: <http://purl.org/dc/terms/> .
@prefix fno: <https://w3id.org/function/ontology#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .

<> a aggr:TransformationCatalog ;
	dct:title "Aggregator transformations" ;
	aggr:hasTransformation <SPARQLEvaluation>, <CopyResource> .

<SPARQLEvaluation>
	a                   fno:Function ;
	fno:name            "A SPARQL query engine"^^xsd:string ;
	dct:description     "Evaluates a SPARQL query over one or more sources and exposes the results as a dataset."^^xsd:string ;
	fno:expects         ( <QueryString> <Sources> ) ;
	fno:returns         ( <Result> ) .

<QueryString>
	a             fno:Parameter ;
	fno:predicate <queryString> ;
	fno:type      xsd:string ;
	fno:required  "true"^^xsd:boolean .

<Sources>
	a             fno:Parameter ;
	fno:predicate <sources> ;
	fno:type      rdf:List ;
	fno:required  "true"^^xsd:boolean .

<Result>
	a             fno:Output ;
	fno:type      dcat:Dataset ;
	fno:predicate <result> .

<CopyResource>
	a                   fno:Function ;
	fno:name            "Copy resource"^^xsd:string ;
	dct:description     "Copies one input resource location and exposes the copied representation as a dataset."^^xsd:string ;
	fno:expects         ( <ResourceLocation> ) ;
	fno:returns         ( <CopiedResource> ) .

<ResourceLocation>
	a             fno:Parameter ;
	fno:predicate <resourceLocation> ;
	fno:type      xsd:anyURI ;
	fno:required  "true"^^xsd:boolean .

<CopiedResource>
	a             fno:Output ;
	fno:type      dcat:Dataset ;
	fno:predicate <copiedResource> .
`
