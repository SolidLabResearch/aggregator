package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"ingress-uma/model"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/piprate/json-gold/ld"
)

// DefaultPolicy stores the complete caller-provided JSON-LD template. ID is a
// management identifier and is deliberately separate from the ODRL uid.
type DefaultPolicy struct {
	ID               string          `json:"id"`
	Document         json.RawMessage `json:"policy"`
	PolicyManagement bool            `json:"-"`
}

type defaultPolicyRequest struct {
	AggregatorID     string          `json:"aggregator_id"`
	UserID           string          `json:"user_id"`
	ASURL            string          `json:"as_url"`
	Assigner         string          `json:"assigner"`
	PolicyManagement bool            `json:"policy_management,omitempty"`
	Document         json.RawMessage `json:"policy"`
}

type defaultPolicySet struct {
	AuthData AggregatorAuthData
	Assigner string
	Policies map[string]DefaultPolicy
}

var (
	defaultPoliciesMu  sync.RWMutex
	defaultPolicies    = map[string]*defaultPolicySet{}
	policyJSONLDLoader = ld.NewCachingDocumentLoader(ld.NewDefaultDocumentLoader(nil))
	blankNodePattern   = regexp.MustCompile(`_:[A-Za-z][A-Za-z0-9_-]*`)
)

func HandleDefaultPolicyRequest(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		handlePostDefaultPolicy(w, r)
	case http.MethodGet:
		handleGetDefaultPolicies(w, r)
	case http.MethodDelete:
		handleDeleteDefaultPolicy(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handlePostDefaultPolicy(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var request defaultPolicyRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(request.AggregatorID) == "" || strings.TrimSpace(request.UserID) == "" ||
		strings.TrimSpace(request.ASURL) == "" || strings.TrimSpace(request.Assigner) == "" {
		http.Error(w, "aggregator_id, user_id, as_url, and assigner are required", http.StatusBadRequest)
		return
	}
	if err := validateDefaultPolicy(request.Document); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	policy := DefaultPolicy{
		ID: uuid.NewString(), Document: append(json.RawMessage(nil), request.Document...),
		PolicyManagement: request.PolicyManagement,
	}
	set := ensureDefaultPolicySet(request)
	defaultPoliciesMu.Lock()
	set.Policies[policy.ID] = policy
	defaultPoliciesMu.Unlock()

	if err := instantiateDefaultPolicy(request.AggregatorID, set, policy); err != nil {
		defaultPoliciesMu.Lock()
		delete(set.Policies, policy.ID)
		defaultPoliciesMu.Unlock()
		_ = recreateAggregatorResources(request.AggregatorID)
		http.Error(w, "Failed to instantiate default policy", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", "/policies/"+policy.ID)
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(policy)
}

func handleGetDefaultPolicies(w http.ResponseWriter, r *http.Request) {
	aggregatorID := strings.TrimSpace(r.URL.Query().Get("aggregator_id"))
	if aggregatorID == "" {
		http.Error(w, "aggregator_id is required", http.StatusBadRequest)
		return
	}
	defaultPoliciesMu.RLock()
	set := defaultPolicies[aggregatorID]
	policies := []DefaultPolicy{}
	if set != nil {
		for _, policy := range set.Policies {
			policies = append(policies, policy)
		}
	}
	defaultPoliciesMu.RUnlock()
	sort.Slice(policies, func(i, j int) bool { return policies[i].ID < policies[j].ID })
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(policies)
}

func handleDeleteDefaultPolicy(w http.ResponseWriter, r *http.Request) {
	aggregatorID := strings.TrimSpace(r.URL.Query().Get("aggregator_id"))
	policyID := strings.TrimSpace(r.URL.Query().Get("id"))
	if aggregatorID == "" || policyID == "" {
		http.Error(w, "aggregator_id and id are required", http.StatusBadRequest)
		return
	}
	defaultPoliciesMu.Lock()
	set := defaultPolicies[aggregatorID]
	if set == nil {
		defaultPoliciesMu.Unlock()
		http.NotFound(w, r)
		return
	}
	policy, ok := set.Policies[policyID]
	if !ok {
		defaultPoliciesMu.Unlock()
		http.NotFound(w, r)
		return
	}
	delete(set.Policies, policyID)
	defaultPoliciesMu.Unlock()

	if err := recreateAggregatorResources(aggregatorID); err != nil {
		defaultPoliciesMu.Lock()
		set.Policies[policyID] = policy
		defaultPoliciesMu.Unlock()
		_ = instantiateDefaultPolicy(aggregatorID, set, policy)
		http.Error(w, "Failed to revoke default policy", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func validateDefaultPolicy(raw json.RawMessage) error {
	var document map[string]interface{}
	if len(raw) == 0 || json.Unmarshal(raw, &document) != nil {
		return errors.New("policy must be a JSON-LD object")
	}
	if _, ok := document["@context"]; !ok {
		return errors.New("policy must define @context")
	}
	if !hasODRLType(document["@type"], "Offer", "Agreement") {
		return errors.New("policy @type must be Offer or Agreement")
	}
	permissionKey, permissions, ok := policyPermissions(document)
	if !ok || permissionKey == "" || len(permissions) == 0 {
		return errors.New("policy must contain at least one permission")
	}
	if forbidden, ok := findForbiddenPolicyField(document, true); ok {
		return fmt.Errorf("default policy must not define %s; the aggregator supplies it", forbidden)
	}
	for _, permission := range permissions {
		if !hasODRLType(permission["@type"], "Permission") {
			return errors.New("each policy permission must have @type Permission")
		}
	}
	return nil
}

func hasODRLType(value interface{}, allowed ...string) bool {
	values := []interface{}{value}
	if array, ok := value.([]interface{}); ok {
		values = array
	}
	for _, candidate := range values {
		text, _ := candidate.(string)
		for _, expected := range allowed {
			if localJSONLDName(text) == strings.ToLower(expected) {
				return true
			}
		}
	}
	return false
}

func policyPermissions(document map[string]interface{}) (string, []map[string]interface{}, bool) {
	for key, value := range document {
		if localJSONLDName(key) != "permission" {
			continue
		}
		items, ok := value.([]interface{})
		if !ok {
			items = []interface{}{value}
		}
		permissions := make([]map[string]interface{}, 0, len(items))
		for _, item := range items {
			permission, ok := item.(map[string]interface{})
			if !ok {
				return key, nil, false
			}
			permissions = append(permissions, permission)
		}
		return key, permissions, true
	}
	return "", nil, false
}

func findForbiddenPolicyField(value interface{}, root bool) (string, bool) {
	switch typed := value.(type) {
	case map[string]interface{}:
		for key, child := range typed {
			if root && key == "@context" {
				continue
			}
			name := localJSONLDName(key)
			if name == "action" || name == "target" || name == "assigner" {
				return key, true
			}
			if field, ok := findForbiddenPolicyField(child, false); ok {
				return field, true
			}
		}
	case []interface{}:
		for _, child := range typed {
			if field, ok := findForbiddenPolicyField(child, false); ok {
				return field, true
			}
		}
	}
	return "", false
}

func localJSONLDName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if index := strings.LastIndexAny(value, "#/:."); index >= 0 {
		return value[index+1:]
	}
	return value
}

func ensureDefaultPolicySet(request defaultPolicyRequest) *defaultPolicySet {
	defaultPoliciesMu.Lock()
	defer defaultPoliciesMu.Unlock()
	set := defaultPolicies[request.AggregatorID]
	if set == nil {
		set = &defaultPolicySet{
			AuthData: AggregatorAuthData{AggregatorID: request.AggregatorID, UserID: request.UserID, AuthzServer: request.ASURL},
			Assigner: request.Assigner,
			Policies: map[string]DefaultPolicy{},
		}
		defaultPolicies[request.AggregatorID] = set
	}
	return set
}

func instantiateDefaultPolicy(aggregatorID string, set *defaultPolicySet, policy DefaultPolicy) error {
	resourceIndexMu.RLock()
	resources := map[string]ResourceData{}
	for id, data := range resourceIndex {
		if data.AggData.AggregatorID == aggregatorID {
			resources[id] = data
		}
	}
	resourceIndexMu.RUnlock()
	for id, data := range resources {
		if !policyAppliesToResource(policy, id, aggregatorID) {
			continue
		}
		if err := instantiatePolicyForResource(policy.Document, data, set.Assigner); err != nil {
			return fmt.Errorf("resource %s: %w", id, err)
		}
	}
	return nil
}

func instantiateDefaultsForResource(resourceID string, data ResourceData) error {
	defaultPoliciesMu.RLock()
	set := defaultPolicies[data.AggData.AggregatorID]
	if set == nil {
		defaultPoliciesMu.RUnlock()
		return nil
	}
	assigner := set.Assigner
	policies := make([]DefaultPolicy, 0, len(set.Policies))
	for _, policy := range set.Policies {
		policies = append(policies, policy)
	}
	defaultPoliciesMu.RUnlock()
	for _, policy := range policies {
		if !policyAppliesToResource(policy, resourceID, data.AggData.AggregatorID) {
			continue
		}
		if err := instantiatePolicyForResource(policy.Document, data, assigner); err != nil {
			return err
		}
	}
	return nil
}

func policyAppliesToResource(policy DefaultPolicy, resourceID, aggregatorID string) bool {
	return policy.PolicyManagement || !isPolicyManagementResource(resourceID, aggregatorID)
}

func isPolicyManagementResource(resourceID, aggregatorID string) bool {
	parsed, err := url.Parse(resourceID)
	if err != nil {
		return false
	}
	prefix := "/" + strings.Trim(aggregatorID, "/") + "/policies"
	return parsed.Path == prefix || strings.HasPrefix(parsed.Path, prefix+"/")
}

func instantiatePolicyForResource(template json.RawMessage, data ResourceData, assigner string) error {
	var document map[string]interface{}
	if err := json.Unmarshal(template, &document); err != nil {
		return err
	}
	_, permissions, ok := policyPermissions(document)
	if !ok {
		return errors.New("policy permissions are invalid")
	}
	actions := make([]string, 0, len(data.Scopes))
	for _, scope := range data.Scopes {
		if action := scopeToAction(scope); action != nil {
			actions = append(actions, action.GetValue())
		}
	}
	if len(actions) == 0 {
		return errors.New("resource has no ODRL actions")
	}
	for _, permission := range permissions {
		setODRLNodeID(permission, "urn:uuid:"+uuid.NewString())
		normalizeODRLIdentifier(permission, "assignee")
		setODRLIdentifier(permission, "target", toValidId(data.UmaID).GetValue())
		setODRLIdentifiers(permission, "action", actions)
		setODRLIdentifier(permission, "assigner", toValidId(assigner).GetValue())
	}
	setODRLNodeID(document, "urn:uuid:"+uuid.NewString())
	return postJSONLDPolicy(data.AggData, document)
}

func setODRLNodeID(object map[string]interface{}, identifier string) {
	for key := range object {
		if localJSONLDName(key) == "uid" {
			delete(object, key)
		}
	}
	object["@id"] = identifier
	object[OdrlPrefix+"uid"] = map[string]interface{}{"@id": identifier}
}

func normalizeODRLIdentifier(object map[string]interface{}, name string) {
	for key, value := range object {
		if localJSONLDName(key) != name {
			continue
		}
		switch typed := value.(type) {
		case string:
			object[key] = toValidId(typed).GetValue()
		case []interface{}:
			for index, item := range typed {
				if identifier, ok := item.(string); ok {
					typed[index] = toValidId(identifier).GetValue()
				}
			}
		}
	}
}

func setODRLIdentifier(object map[string]interface{}, name, identifier string) {
	for key := range object {
		if localJSONLDName(key) == name {
			object[key] = identifier
			return
		}
	}
	object[OdrlPrefix+name] = map[string]interface{}{"@id": identifier}
}

func setODRLIdentifiers(object map[string]interface{}, name string, identifiers []string) {
	for key := range object {
		if localJSONLDName(key) == name {
			object[key] = identifiers
			return
		}
	}
	values := make([]interface{}, 0, len(identifiers))
	for _, identifier := range identifiers {
		values = append(values, map[string]interface{}{"@id": identifier})
	}
	object[OdrlPrefix+name] = values
}

func postJSONLDPolicy(authData AggregatorAuthData, document map[string]interface{}) error {
	processor := ld.NewJsonLdProcessor()
	options := ld.NewJsonLdOptions("")
	options.Format = "application/n-quads"
	options.DocumentLoader = policyJSONLDLoader
	rdf, err := processor.ToRDF(document, options)
	if err != nil {
		return fmt.Errorf("convert JSON-LD policy to RDF: %w", err)
	}
	nquads, ok := rdf.(string)
	if !ok {
		return errors.New("JSON-LD processor returned an unexpected result")
	}
	nquads = skolemizeNQuads(nquads)
	request, err := http.NewRequest(http.MethodPost, authData.AuthzServer+"/policies", bytes.NewBufferString(nquads))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/n-quads")
	request.Header.Set("Authorization", UserAuthHeader(authData.AggregatorID, authData.UserID))
	response, err := model.HttpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(response.Body)
		return fmt.Errorf("policy endpoint returned %d: %s", response.StatusCode, body)
	}
	return nil
}

func skolemizeNQuads(nquads string) string {
	identifiers := map[string]string{}
	return blankNodePattern.ReplaceAllStringFunc(nquads, func(label string) string {
		identifier, ok := identifiers[label]
		if !ok {
			identifier = "<urn:uuid:" + uuid.NewString() + ">"
			identifiers[label] = identifier
		}
		return identifier
	})
}

func recreateAggregatorResources(aggregatorID string) error {
	resourceIndexMu.RLock()
	resources := map[string]ResourceData{}
	for id, data := range resourceIndex {
		if data.AggData.AggregatorID == aggregatorID {
			resources[id] = data
		}
	}
	resourceIndexMu.RUnlock()
	for id, data := range resources {
		if err := deleteResource(id); err != nil {
			return err
		}
		if err := createResource(data.AggData, id, data.Scopes); err != nil {
			return err
		}
	}
	return nil
}
