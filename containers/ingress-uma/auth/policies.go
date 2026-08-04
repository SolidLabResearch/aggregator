package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"ingress-uma/model"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/maartyman/rdfgo"
	"github.com/sirupsen/logrus"
)

var ExPrefix = "http://example.org/"
var OdrlPrefix = "http://www.w3.org/ns/odrl/2/"
var idPrefix = "http://example.com/id/"
var RdfType = rdfgo.NewNamedNode("http://www.w3.org/1999/02/22-rdf-syntax-ns#type")

// Temp public solution
var PublicId = "urn:solidlab:uma:id:anonymous"

func HandlePolicyRequest(w http.ResponseWriter, r *http.Request) {
	// Only accept POST requests
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var reqData struct {
		ASUrl      string   `json:"as_url"`
		ResourceID string   `json:"resource_id"`
		Scopes     []string `json:"scopes"`
		Assignee   string   `json:"assignee"`
		Assigner   string   `json:"assigner"`
		ClientIDs  []string `json:"client_ids"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqData); err != nil {
		logrus.WithError(err).Warn("Invalid JSON in request body")
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	scopes := stringsToScopes(reqData.Scopes)

	assignee := reqData.Assignee
	if strings.TrimSpace(assignee) == "" {
		assignee = PublicId
	}

	clients := reqData.ClientIDs
	if clients == nil {
		clients = []string{}
	}

	logrus.WithFields(logrus.Fields{
		"issuer":      reqData.ASUrl,
		"resource_id": reqData.ResourceID,
		"scopes":      reqData.Scopes,
		"assignee":    assignee,
		"assigner":    reqData.Assigner,
		"client_ids":  reqData.ClientIDs,
	}).Info("Received policy request")

	if err := createPolicy(
		reqData.ASUrl,
		reqData.ResourceID,
		scopes,
		assignee,
		reqData.Assigner,
		clients,
	); err != nil {
		logrus.WithError(err).Error("Failed to create UMA policy")
		http.Error(w, "Failed to create policy", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func createPolicy(
	asUrl string,
	resourceId string,
	scopes []Scope,
	assignee string,
	assigner string,
	clients []string,
) error {
	// Policy URI
	policyUri := asUrl + "/policies"

	// Get UMA ID
	resourceIndexMu.RLock()
	data, ok := resourceIndex[resourceId]
	resourceIndexMu.RUnlock()
	if !ok {
		return fmt.Errorf("resource ID %s not registered, cannot create policy", resourceId)
	}

	// Get Aggregator ID and User ID
	aggregatorID := data.AggData.AggregatorID
	userID := data.AggData.UserID

	// Define policies
	policyStore := rdfgo.NewStore()
	if len(clients) == 0 {
		permissionUri := definePermission(policyStore, data.UmaID, scopes, assignee, assigner)
		definePolicy(policyStore, permissionUri)
	} else {
		for _, clientId := range clients {
			permissionUri := definePermission(policyStore, data.UmaID, scopes, assignee, assigner)
			defineClientConstraint(policyStore, clientId, permissionUri)
			definePolicy(policyStore, permissionUri)
		}
	}

	// Serialize policies to n-quads
	stream := policyStore.Match(nil, nil, nil, nil)
	options := rdfgo.WriterOptions{Format: "n-quads"}

	var buf bytes.Buffer
	_, err := rdfgo.Write(stream, &buf, options)
	if err != nil {
		return fmt.Errorf("failed to serialize N-Quads: %w", err)
	}

	// Send request
	req, err := http.NewRequest("POST", policyUri, &buf)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/n-quads")
	req.Header.Set("Authorization", UserAuthHeader(aggregatorID, userID))
	logrus.WithFields(logrus.Fields{
		"policy_uri": policyUri,
		"policy":     buf.String(),
	}).Infof(`Requesting policy for %s`, resourceId)

	resp, err := model.HttpClient.Do(req)
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

func defineClientConstraint(store rdfgo.Store, client string, permissionUri rdfgo.INamedNode) {
	constraintUri := rdfgo.NewNamedNode(ExPrefix + uuid.NewString())

	store.AddQuadFromTerms(
		constraintUri,
		rdfgo.NewNamedNode(OdrlPrefix+"leftOperand"),
		rdfgo.NewNamedNode(OdrlPrefix+"purpose"),
		nil,
	)

	store.AddQuadFromTerms(
		constraintUri,
		rdfgo.NewNamedNode(OdrlPrefix+"operator"),
		rdfgo.NewNamedNode(OdrlPrefix+"eq"),
		nil,
	)

	store.AddQuadFromTerms(
		constraintUri,
		rdfgo.NewNamedNode(OdrlPrefix+"rightOperand"),
		toValidId(client),
		nil,
	)

	// Client Constraint
	store.AddQuadFromTerms(
		permissionUri,
		rdfgo.NewNamedNode(OdrlPrefix+"constraint"),
		constraintUri,
		nil,
	)
}

func definePermission(store rdfgo.Store, umaId string, scopes []Scope, assignee string, assigner string) rdfgo.INamedNode {
	permissionUri := rdfgo.NewNamedNode(ExPrefix + uuid.NewString())

	store.AddQuadFromTerms(
		permissionUri,
		RdfType,
		rdfgo.NewNamedNode(OdrlPrefix+"Permission"),
		nil,
	)

	// Permissioned actions
	for _, scope := range scopes {
		action := scopeToAction(scope)
		if action != nil {
			store.AddQuadFromTerms(
				permissionUri,
				rdfgo.NewNamedNode(OdrlPrefix+"action"),
				action,
				nil,
			)
		}
	}

	// Target resource
	store.AddQuadFromTerms(
		permissionUri,
		rdfgo.NewNamedNode(OdrlPrefix+"target"),
		rdfgo.NewNamedNode(umaId),
		nil,
	)

	// Assignee
	store.AddQuadFromTerms(
		permissionUri,
		rdfgo.NewNamedNode(OdrlPrefix+"assignee"),
		toValidId(assignee),
		nil,
	)

	// Assigner
	store.AddQuadFromTerms(
		permissionUri,
		rdfgo.NewNamedNode(OdrlPrefix+"assigner"),
		toValidId(assigner),
		nil,
	)

	return permissionUri
}

func definePolicy(store rdfgo.Store, permissionUri rdfgo.INamedNode) {
	policyUri := rdfgo.NewNamedNode(ExPrefix + uuid.NewString())

	store.AddQuadFromTerms(
		policyUri,
		RdfType,
		rdfgo.NewNamedNode(OdrlPrefix+"Agreement"),
		nil,
	)

	store.AddQuadFromTerms(
		policyUri,
		rdfgo.NewNamedNode(OdrlPrefix+"uid"),
		policyUri,
		nil,
	)

	store.AddQuadFromTerms(
		policyUri,
		rdfgo.NewNamedNode(OdrlPrefix+"permission"),
		permissionUri,
		nil,
	)
}

func toValidId(id string) rdfgo.INamedNode {
	parsed, err := url.Parse(id)

	// A valid absolute URI must:
	// - parse without error
	// - have a scheme (http, https, urn, etc.)
	// - have a host (for http/https)
	if err == nil && parsed.Scheme != "" {
		// For HTTP-style URIs, also require host
		if parsed.Scheme == "http" || parsed.Scheme == "https" {
			if parsed.Host != "" {
				return rdfgo.NewNamedNode(id)
			}
		} else {
			// For non-http schemes (urn, did, etc.)
			return rdfgo.NewNamedNode(id)
		}
	}

	// Otherwise treat as local ID and prefix it
	return rdfgo.NewNamedNode(idPrefix + strings.TrimSpace(id))
}
