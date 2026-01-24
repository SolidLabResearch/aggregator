package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

var Ex = "http://example.org/"
var Odrl = "http://www.w3.org/ns/odrl/2/"
// TODO: make configurable
var TrustedClients = []string{
	"moveup-app",
}

// Temp public solution
var PublicId = "urn:solidlab:uma:id:anonymous"

func HandlePolicyRequest(w http.ResponseWriter, r *http.Request) {
	// Only accept POST requests
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var reqData struct {
		Issuer     string   `json:"issuer"`
		ResourceID string   `json:"resource_id"`
		Scopes     []string `json:"scopes"`
		UserID     string   `json:"user_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqData); err != nil {
		logrus.WithError(err).Warn("Invalid JSON in request body")
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	scopes := stringsToScopes(reqData.Scopes)

	logrus.WithFields(logrus.Fields{
		"issuer":      reqData.Issuer,
		"resource_id": reqData.ResourceID,
		"scopes":      reqData.Scopes,
		"user_id":     reqData.UserID,
	}).Info("Received policy request")

	// Decide user and clients for the policy
	var userID string
	var clients []string
	if strings.TrimSpace(reqData.UserID) == "" {
		userID = PublicId
		clients = []string{}
	} else {
		userID = reqData.UserID
		clients = TrustedClients
	}

	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader == "" {
		http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
		return
	}

	if err := createPolicy(reqData.Issuer, reqData.ResourceID, scopes, userID, clients, authHeader); err != nil {
		logrus.WithError(err).Error("Failed to create UMA policy")
		http.Error(w, "Failed to create policy", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// createPolicy registers a policy for a UMA resource.
// - issuer: UMA AS base URL (used to build the /policies endpoint and look up UMA resource IDs).
// - resourceId: external resource URL (mapped to the UMA resource ID in idIndex).
// - scopes: requested UMA scopes; translated to ODRL actions in the policy body.
// - userId: subject that should receive access (becomes assignee/assigner in the policy body).
// - clients: optional allowed clients (used by legacy/Keycloak policy generation; ignored for A4DS).
// - authHeader: credentials to authenticate the policy write at the UMA server.
func createPolicy(issuer string, resourceId string, scopes []Scope, userId string, clients []string, authHeader string) error {
	// Policy URI
	policyUri := issuer + "/policies"

	// Get UMA ID
	UmaId := idIndex[resourceId]
	if UmaId == "" {
		return fmt.Errorf("resource ID %s not registered, cannot create policy", resourceId)
	}

	assignerID := userId
	if headerWebID := webIDFromAuthHeader(authHeader); headerWebID != "" {
		assignerID = headerWebID
	}

	// Define policies
	policyBody := buildPolicyBody(UmaId, scopes, userId, assignerID)
	contentType := "text/turtle"

	// Send request
	req, err := http.NewRequest("POST", policyUri, strings.NewReader(policyBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", contentType)
	logrus.WithFields(logrus.Fields{
		"policy_uri": policyUri,
		"policy":     policyBody,
	}).Infof(`Requesting policy for %s`, resourceId)

	policyAuthHeader := strings.TrimSpace(authHeader)
	if policyAuthHeader == "" {
		return fmt.Errorf("authorization header is required for policy requests")
	}

	req.Header.Set("Authorization", policyAuthHeader)

	clientHttp := &http.Client{}
	resp, err := clientHttp.Do(req)
	if err != nil {
		return fmt.Errorf("policy request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("policy endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// TODO: improve policy body generation
func buildPolicyBody(resourceId string, scopes []Scope, userId string, assignerID string) string {
	policyID := "policy-" + uuid.NewString()
	permissionID := "permission-" + uuid.NewString()
	actions := actionList(scopes)
	if len(actions) == 0 {
		actions = []string{"odrl:read"}
	}

	builder := strings.Builder{}
	builder.WriteString("@prefix ex: <http://example.org/>.\n")
	builder.WriteString("@prefix odrl: <http://www.w3.org/ns/odrl/2/> .\n")
	builder.WriteString("@prefix dct: <http://purl.org/dc/terms/>.\n\n")

	builder.WriteString(fmt.Sprintf("ex:%s a odrl:Agreement ;\n", policyID))
	builder.WriteString(fmt.Sprintf("               odrl:uid ex:%s ;\n", policyID))
	builder.WriteString(fmt.Sprintf("               odrl:permission ex:%s .\n", permissionID))
	builder.WriteString("\n")
	builder.WriteString(fmt.Sprintf("ex:%s a odrl:Permission ;\n", permissionID))
	builder.WriteString(fmt.Sprintf("              odrl:action %s ;\n", strings.Join(actions, ", ")))
	builder.WriteString(fmt.Sprintf("              odrl:target %s ;\n", formatIri(resourceId)))
	builder.WriteString(fmt.Sprintf("              odrl:assignee %s ;\n", formatIri(userId)))
	builder.WriteString(fmt.Sprintf("              odrl:assigner %s .\n", formatIri(assignerID)))

	return builder.String()
}

func actionList(scopes []Scope) []string {
	seen := make(map[string]struct{}, len(scopes))
	actions := []string{}
	for _, scope := range scopes {
		action := scopeToAction(scope)
		if action == nil {
			continue
		}
		actionValue := action.GetValue()
		if strings.HasPrefix(actionValue, Odrl) {
			actionValue = "odrl:" + strings.TrimPrefix(actionValue, Odrl)
		} else {
			actionValue = formatIri(actionValue)
		}
		if _, ok := seen[actionValue]; ok {
			continue
		}
		seen[actionValue] = struct{}{}
		actions = append(actions, actionValue)
	}
	return actions
}

func formatIri(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "<>"
	}
	if strings.HasPrefix(trimmed, "<") && strings.HasSuffix(trimmed, ">") {
		return trimmed
	}
	return "<" + trimmed + ">"
}

func webIDFromAuthHeader(authHeader string) string {
	trimmed := strings.TrimSpace(authHeader)
	if trimmed == "" {
		return ""
	}
	lower := strings.ToLower(trimmed)
	if !strings.HasPrefix(lower, "webid ") {
		return ""
	}
	encoded := strings.TrimSpace(trimmed[6:])
	if encoded == "" {
		return ""
	}
	decoded, err := url.QueryUnescape(encoded)
	if err == nil && strings.TrimSpace(decoded) != "" {
		return decoded
	}
	return encoded
}
