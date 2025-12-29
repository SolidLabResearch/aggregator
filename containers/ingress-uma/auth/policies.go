package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/maartyman/rdfgo"
	"github.com/sirupsen/logrus"
)

var Ex = "http://example.org/"
var Odrl = "http://www.w3.org/ns/odrl/2/"
var RdfType = rdfgo.NewNamedNode("http://www.w3.org/1999/02/22-rdf-syntax-ns#type")

// TODO: Create web id for aggregator
var DummyWebID = "https://aggregator.local/profile/card#me"

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

	if err := createPolicy(reqData.Issuer, reqData.ResourceID, scopes, userID, clients); err != nil {
		logrus.WithError(err).Error("Failed to create UMA policy")
		http.Error(w, "Failed to create policy", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func createPolicy(issuer string, resourceId string, scopes []Scope, userId string, clients []string) error {
	// Policy URI
	policyUri := issuer + "/policies"

	// Get UMA ID
	UmaId := idIndex[resourceId]
	if UmaId == "" {
		return fmt.Errorf("resource ID %s not registered, cannot create policy", resourceId)
	}

	// Define policies
	policyStore := rdfgo.NewStore()
	if len(clients) == 0 {
		permissionUri := definePermission(policyStore, UmaId, scopes, userId)
		definePolicy(policyStore, permissionUri)
	} else {
		for _, clientId := range clients {
			permissionUri := definePermission(policyStore, UmaId, scopes, userId)
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
	req.Header.Set("Authorization", DummyWebID)
	logrus.WithFields(logrus.Fields{
		"policy_uri": policyUri,
		"policy":     buf.String(),
	}).Infof(`Requesting policy for %s`, resourceId)

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

func defineClientConstraint(store rdfgo.Store, client string, permissionUri rdfgo.INamedNode) {
	constraintUri := rdfgo.NewNamedNode(Ex + uuid.NewString())

	store.AddQuadFromTerms(
		constraintUri,
		rdfgo.NewNamedNode(Odrl+"leftOperand"),
		rdfgo.NewNamedNode(Odrl+"purpose"),
		nil,
	)

	store.AddQuadFromTerms(
		constraintUri,
		rdfgo.NewNamedNode(Odrl+"operator"),
		rdfgo.NewNamedNode(Odrl+"eq"),
		nil,
	)

	store.AddQuadFromTerms(
		constraintUri,
		rdfgo.NewNamedNode(Odrl+"rightOperand"),
		rdfgo.NewNamedNode(client),
		nil,
	)

	// Client Constraint
	store.AddQuadFromTerms(
		permissionUri,
		rdfgo.NewNamedNode(Odrl+"constraint"),
		constraintUri,
		nil,
	)
}

func definePermission(store rdfgo.Store, umaId string, scopes []Scope, userId string) rdfgo.INamedNode {
	permissionUri := rdfgo.NewNamedNode(Ex + uuid.NewString())

	store.AddQuadFromTerms(
		permissionUri,
		RdfType,
		rdfgo.NewNamedNode(Odrl+"Permission"),
		nil,
	)

	// Permissioned actions
	for _, scope := range scopes {
		action := scopeToAction(scope)
		if action != nil {
			store.AddQuadFromTerms(
				permissionUri,
				rdfgo.NewNamedNode(Odrl+"action"),
				action,
				nil,
			)
		}
	}

	// Target resource
	store.AddQuadFromTerms(
		permissionUri,
		rdfgo.NewNamedNode(Odrl+"target"),
		rdfgo.NewNamedNode(umaId),
		nil,
	)

	// Assignee
	store.AddQuadFromTerms(
		permissionUri,
		rdfgo.NewNamedNode(Odrl+"assignee"),
		rdfgo.NewNamedNode(userId),
		nil,
	)

	// Assigner
	store.AddQuadFromTerms(
		permissionUri,
		rdfgo.NewNamedNode(Odrl+"assigner"),
		rdfgo.NewNamedNode(DummyWebID), // Assigner is the aggregator
		nil,
	)

	return permissionUri
}

func definePolicy(store rdfgo.Store, permissionUri rdfgo.INamedNode) {
	policyUri := rdfgo.NewNamedNode(Ex + uuid.NewString())

	store.AddQuadFromTerms(
		policyUri,
		RdfType,
		rdfgo.NewNamedNode(Odrl+"Agreement"),
		nil,
	)

	store.AddQuadFromTerms(
		policyUri,
		rdfgo.NewNamedNode(Odrl+"uid"),
		policyUri,
		nil,
	)

	store.AddQuadFromTerms(
		policyUri,
		rdfgo.NewNamedNode(Odrl+"permission"),
		permissionUri,
		nil,
	)
}
