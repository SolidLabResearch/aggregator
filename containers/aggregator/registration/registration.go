package registration

import (
	"aggregator/config"
	"aggregator/types"
	"aggregator/vars"
	"context"
	"encoding/base64"
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

var (
	users   = make(map[string]*types.User)
	userMux sync.Mutex
)

// registrationHandler now accepts POST (form or JSON) and returns a redirect to the IdP auth endpoint
func RegistrationHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req types.RegistrationRequest

	// Accept either form values or JSON body for convenience
	contentType := r.Header.Get("Content-Type")
	if contentType == "application/json" || strings.HasPrefix(contentType, "application/json;") {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
	} else {
		// Parse form
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form body", http.StatusBadRequest)
			return
		}
		req.UserIdp = r.FormValue("openid_provider")
		req.AuthzServerURL = r.FormValue("as_url")
		req.SuccessRedirect = r.FormValue("success_redirect")
		req.FailRedirect = r.FormValue("fail_redirect")
	}

	if req.UserIdp == "" || req.AuthzServerURL == "" || req.SuccessRedirect == "" || req.FailRedirect == "" {
		http.Error(w, "missing required fields", http.StatusBadRequest)
		return
	}

	// Discover auth endpoint
	authURL, err := getAuthEndpoint(req.UserIdp)
	if err != nil {
		logrus.WithError(err).Error("Failed to get authn endpoint")
		http.Error(w, "Failed to get authn endpoint", http.StatusInternalServerError)
		return
	}

	state, err := generateRandomState()
	if err != nil {
		logrus.WithError(err).Error("Failed to generate state")
		http.Error(w, "Failed to generate state", http.StatusInternalServerError)
		return
	}

	// Store the registration request for callback (state -> req mapping)
	stateStore[state] = req

	// Build auth URL with parameters
	params := url.Values{
		"redirect_uri":  {fmt.Sprintf("%s://%s/registration/callback", vars.Protocol, vars.ExternalHost)},
		"state":         {state},
		"scope":         {"openid profile email offline_access"},
		"response_type": {"code"},
		"client_id":     {vars.ClientId},
	}
	redirectTo := fmt.Sprintf("%s?%s", authURL, params.Encode())

	// Redirect browser to IdP authorization endpoint
	http.Redirect(w, r, redirectTo, http.StatusFound)
}

func RegistrationCallback(w http.ResponseWriter, r *http.Request, mux *http.ServeMux) {
	logrus.Debug("Entered registrationCallback")

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		logrus.Warnf("Missing code or state: code='%s', state='%s'", code, state)
		http.Error(w, "Missing code or state", http.StatusBadRequest)
		return
	}
	logrus.Debugf("Received code and state: code='%s', state='%s'", code, state)

	req, ok := stateStore[state]
	if !ok {
		logrus.Warnf("Invalid state: %s", state)
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}
	delete(stateStore, state)

	tokenEndpoint, err := getTokenEndpoint(req.UserIdp)
	if err != nil {
		logrus.WithError(err).Error("Failed to get token endpoint")
		http.Redirect(w, r, req.FailRedirect, http.StatusFound)
		return
	}
	logrus.Infof("Using token endpoint: %s", tokenEndpoint)

	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {fmt.Sprintf("%s://%s/registration/callback", vars.Protocol, vars.ExternalHost)},
		"client_id":     {vars.ClientId},
		"client_secret": {vars.ClientSecret},
	}

	resp, err := http.PostForm(tokenEndpoint, data)
	if err != nil {
		logrus.WithError(err).Error("Token exchange failed")
		http.Redirect(w, r, req.FailRedirect, http.StatusFound)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		logrus.Errorf("Token endpoint returned %d: %s", resp.StatusCode, string(body))
		http.Redirect(w, r, req.FailRedirect, http.StatusFound)
		return
	}

	var tokenResp struct {
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		logrus.WithError(err).Error("Failed to parse token response JSON")
		http.Redirect(w, r, req.FailRedirect, http.StatusFound)
		return
	}
	logrus.Info("Successfully obtained tokens")

	idToken, err := verifyToken(tokenResp.IDToken, req.UserIdp)
	if err != nil {
		logrus.WithError(err).Error("Failed to verify ID token")
		http.Redirect(w, r, req.FailRedirect, http.StatusFound)
		return
	}

	userId, err := validateToken(idToken, req.UserIdp)
	if err != nil {
		logrus.WithError(err).Error("Failed to validate ID token")
		http.Redirect(w, r, req.FailRedirect, http.StatusFound)
		return
	}
	logrus.Infof("ID token validated for user: %s", userId)

	user := types.User{
		UserId:         userId,
		RefreshToken:   tokenResp.RefreshToken,
		AuthzServerURL: req.AuthzServerURL,
	}

	userMux.Lock()
	defer userMux.Unlock()

	if _, exists := users[user.UserId]; exists {
		logrus.Warnf("User already exists: %s", user.UserId)
		http.Redirect(w, r, req.FailRedirect, http.StatusFound)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ns, err := createNamespace(user, ctx)
	if err != nil {
		logrus.WithError(err).Errorf("Failed to create namespace for user: %s", user.UserId)
		http.Redirect(w, r, req.FailRedirect, http.StatusFound)
		return
	}
	user.Namespace = ns
	logrus.Infof("Namespace '%s' created for user: %s", ns, user.UserId)

	if err := createUMAProxy(1, ns, tokenEndpoint, user.RefreshToken, ctx); err != nil {
		logrus.WithError(err).Errorf("Failed to deploy Egress UMA for user: %s", user.UserId)
		http.Redirect(w, r, req.FailRedirect, http.StatusFound)
		return
	}
	logrus.Infof("Egress UMA deployed successfully for user: %s in namespace %s", user.UserId, ns)

	if err := config.InitUserConfiguration(mux, user); err != nil {
		logrus.WithError(err).Errorf("Failed to initialize user configuration for user: %s", user.UserId)
		http.Redirect(w, r, req.FailRedirect, http.StatusInternalServerError)
		return
	}

	users[user.UserId] = &user
	logrus.Infof("User stored successfully: %s", user.UserId)

	// Prepare endpoints payload
	endpoints := user.ConfigEndpoints()
	endpointsJSON, _ := json.Marshal(endpoints)
	payload := base64.StdEncoding.EncodeToString(endpointsJSON)

	successURL, err := url.Parse(req.SuccessRedirect)
	if err != nil {
		logrus.WithError(err).Error("Invalid success redirect URL")
		http.Redirect(w, r, req.FailRedirect, http.StatusBadRequest)
		return
	}
	q := successURL.Query()
	q.Set("payload", url.QueryEscape(payload))
	successURL.RawQuery = q.Encode()

	logrus.Infof("Redirecting user %s to success URL", user.UserId)
	http.Redirect(w, r, successURL.String(), http.StatusFound)
}
