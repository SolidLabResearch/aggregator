package config

import (
	"aggregator/auth"
	"aggregator/model"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"aggregator/util"
	"github.com/google/uuid"
)

func InitDefaultPolicies(mux *http.ServeMux) error {
	if model.Owner.AuthzServerURL == "" {
		mux.HandleFunc("/policies", handlePolicies)
		mux.HandleFunc("/policies/", handlePolicies)
		return nil
	}
	ownerPolicy, err := auth.CreateOwnerDefaultPolicy(ownerPolicyDocument())
	if err != nil {
		return err
	}
	if err := auth.RegisterResource(model.ExternalBaseURL()+"/policies", []model.Scope{model.Read, model.Create, model.Delete}); err != nil {
		return err
	}
	if err := auth.RegisterResource(model.ExternalBaseURL()+"/policies/"+ownerPolicy.ID, []model.Scope{model.Delete}); err != nil {
		return err
	}
	if err := auth.RegisterResource(model.ExternalBaseURL()+"/policies/grants", []model.Scope{model.Read, model.Create, model.Delete}); err != nil {
		return err
	}
	mux.HandleFunc("/policies", handlePolicies)
	mux.HandleFunc("/policies/", handlePolicies)
	return nil
}

func ownerPolicyDocument() json.RawMessage {
	document, _ := json.Marshal(map[string]interface{}{
		"@context": "http://www.w3.org/ns/odrl.jsonld",
		"@type":    "Agreement",
		"uid":      "urn:uuid:" + uuid.NewString(),
		"permission": []interface{}{map[string]interface{}{
			"@type":    "Permission",
			"assignee": model.Owner.UserId,
		}},
	})
	return document
}

func handlePolicies(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/policies/grants" || strings.HasPrefix(r.URL.Path, "/policies/grants/") {
		handleRoleGrants(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		if r.URL.Path != "/policies" {
			http.NotFound(w, r)
			return
		}
		policies, err := auth.ListDefaultPolicies()
		if err != nil {
			http.Error(w, "Failed to list policies", http.StatusBadGateway)
			return
		}
		documents := make([]map[string]interface{}, 0, len(policies))
		for _, policy := range policies {
			if policy.Selector != nil {
				continue
			}
			var document map[string]interface{}
			if err := json.Unmarshal(policy.Document, &document); err != nil {
				http.Error(w, "Failed to decode stored policy", http.StatusBadGateway)
				return
			}
			document["https://w3id.org/aggregator#policyId"] = policy.ID
			documents = append(documents, document)
		}
		w.Header().Set("Content-Type", "application/ld+json")
		_ = json.NewEncoder(w).Encode(documents)
	case http.MethodPost:
		if r.URL.Path != "/policies" {
			http.NotFound(w, r)
			return
		}
		if mediaType := strings.ToLower(r.Header.Get("Content-Type")); !strings.Contains(mediaType, "application/ld+json") {
			http.Error(w, "Content-Type must be application/ld+json", http.StatusUnsupportedMediaType)
			return
		}
		defer r.Body.Close()
		document, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "Failed to read policy", http.StatusBadRequest)
			return
		}
		if !json.Valid(document) {
			http.Error(w, "Invalid JSON-LD body", http.StatusBadRequest)
			return
		}
		created, err := auth.CreateDefaultPolicy(document)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to create policy: %v", err), http.StatusBadRequest)
			return
		}
		policyURL := model.ExternalBaseURL() + "/policies/" + created.ID
		if err := auth.RegisterResource(policyURL, []model.Scope{model.Delete}); err != nil {
			_ = auth.DeleteDefaultPolicy(created.ID)
			http.Error(w, "Failed to protect policy", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/ld+json")
		w.Header().Set("Location", policyURL)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(created.Document)
	case http.MethodDelete:
		id := strings.TrimPrefix(r.URL.Path, "/policies/")
		if id == "" || strings.Contains(id, "/") {
			http.NotFound(w, r)
			return
		}
		if ok, err := policyHasSelector(id, false); err != nil {
			http.Error(w, "Failed to inspect policy", http.StatusBadGateway)
			return
		} else if !ok {
			http.NotFound(w, r)
			return
		}
		if err := auth.DeleteDefaultPolicy(id); err != nil {
			if err == auth.ErrDefaultPolicyNotFound {
				http.NotFound(w, r)
				return
			}
			http.Error(w, "Failed to delete policy", http.StatusBadGateway)
			return
		}
		if err := auth.DeleteResource(model.ExternalBaseURL() + "/policies/" + id); err != nil {
			http.Error(w, "Policy deleted but its resource registration could not be removed", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleRoleGrants(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if r.URL.Path != "/policies/grants" {
			http.NotFound(w, r)
			return
		}
		policies, err := auth.ListDefaultPolicies()
		if err != nil {
			http.Error(w, "Failed to list role grants", http.StatusBadGateway)
			return
		}
		result := []map[string]interface{}{}
		for _, policy := range policies {
			if policy.Selector == nil {
				continue
			}
			var document map[string]interface{}
			if err := json.Unmarshal(policy.Document, &document); err != nil {
				http.Error(w, "Failed to decode stored role grant", http.StatusBadGateway)
				return
			}
			document["https://w3id.org/aggregator#grantId"] = policy.ID
			document["https://w3id.org/aggregator#service"] = policy.Selector.Service
			document["https://w3id.org/aggregator#role"] = policy.Selector.Role
			result = append(result, document)
		}
		w.Header().Set("Content-Type", "application/ld+json")
		_ = json.NewEncoder(w).Encode(result)
	case http.MethodPost:
		if r.URL.Path != "/policies/grants" {
			http.NotFound(w, r)
			return
		}
		if !strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "application/ld+json") {
			http.Error(w, "Content-Type must be application/ld+json", http.StatusUnsupportedMediaType)
			return
		}
		selector, err := resolveRoleSelector(r.URL.Query().Get("service"), r.URL.Query().Get("role"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer r.Body.Close()
		document, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil || !json.Valid(document) {
			http.Error(w, "Invalid JSON-LD body", http.StatusBadRequest)
			return
		}
		created, err := auth.CreateRoleGrant(document, selector)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to create role grant: %v", err), http.StatusBadRequest)
			return
		}
		grantURL := model.ExternalBaseURL() + "/policies/grants/" + created.ID
		if err := auth.RegisterResource(grantURL, []model.Scope{model.Delete}); err != nil {
			_ = auth.DeleteDefaultPolicy(created.ID)
			http.Error(w, "Failed to protect role grant", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/ld+json")
		w.Header().Set("Location", grantURL)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(created.Document)
	case http.MethodDelete:
		id := strings.TrimPrefix(r.URL.Path, "/policies/grants/")
		if id == "" || strings.Contains(id, "/") {
			http.NotFound(w, r)
			return
		}
		if ok, err := policyHasSelector(id, true); err != nil {
			http.Error(w, "Failed to inspect role grant", http.StatusBadGateway)
			return
		} else if !ok {
			http.NotFound(w, r)
			return
		}
		if err := auth.DeleteDefaultPolicy(id); err != nil {
			if err == auth.ErrDefaultPolicyNotFound {
				http.NotFound(w, r)
			} else {
				http.Error(w, "Failed to delete role grant", http.StatusBadGateway)
			}
			return
		}
		if err := auth.DeleteResource(model.ExternalBaseURL() + "/policies/grants/" + id); err != nil {
			http.Error(w, "Role grant deleted but its resource registration could not be removed", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func policyHasSelector(id string, want bool) (bool, error) {
	policies, err := auth.ListDefaultPolicies()
	if err != nil {
		return false, err
	}
	for _, policy := range policies {
		if policy.ID == id {
			return (policy.Selector != nil) == want, nil
		}
	}
	return false, nil
}

func resolveRoleSelector(serviceRef, roleRef string) (auth.PolicySelector, error) {
	if strings.TrimSpace(serviceRef) == "" || strings.TrimSpace(roleRef) == "" {
		return auth.PolicySelector{}, fmt.Errorf("service and role are required")
	}
	if decoded, err := url.QueryUnescape(serviceRef); err == nil {
		serviceRef = decoded
	}
	if decoded, err := url.QueryUnescape(roleRef); err == nil {
		roleRef = decoded
	}
	collection := activeServiceCollection
	if collection == nil {
		return auth.PolicySelector{}, fmt.Errorf("service collection is not initialized")
	}
	collection.servicesMu.RLock()
	var service *model.Service
	for _, candidate := range collection.services {
		if candidate.InstanceID == serviceRef || candidate.FullPath == serviceRef || strings.TrimSuffix(candidate.FullPath, "/") == strings.TrimSuffix(serviceRef, "/") || strings.TrimPrefix(candidate.InstanceID, "services-") == serviceRef {
			service = candidate
			break
		}
	}
	collection.servicesMu.RUnlock()
	if service == nil {
		return auth.PolicySelector{}, fmt.Errorf("unknown deployed service %q", serviceRef)
	}
	profile := service.Deployment.Definition.ServiceProfile
	if profile == nil {
		return auth.PolicySelector{}, fmt.Errorf("service has no profile access roles")
	}
	roleName := roleRef
	for name, role := range profile.AccessRoles {
		if roleRef == role.URI {
			roleName = name
			break
		}
	}
	role, ok := profile.AccessRoles[roleName]
	if !ok {
		return auth.PolicySelector{}, fmt.Errorf("service does not provide access role %q", roleRef)
	}
	resources := map[string][]model.Scope{}
	for _, endpoint := range service.Deployment.Definition.Endpoints {
		resourceURL := util.JoinPaths(service.FullPath, endpoint.Path)
		for _, operation := range endpoint.Operations {
			if !containsString(operation.AccessRoles, roleName) {
				continue
			}
			actions := append([]model.Scope(nil), operation.Scopes...)
			if len(actions) == 0 {
				actions = defaultEndpointScopes(operation.Method)
			}
			resources[resourceURL] = uniqueScopes(append(resources[resourceURL], actions...))
		}
	}
	for _, dataset := range service.Deployment.Definition.Datasets {
		for _, distribution := range dataset.Distributions {
			if containsString(distribution.AccessRoles, roleName) {
				resourceURL := util.JoinPaths(service.FullPath, distribution.Path)
				resources[resourceURL] = uniqueScopes(append(resources[resourceURL], model.Read))
			}
		}
	}
	if len(resources) == 0 {
		return auth.PolicySelector{}, fmt.Errorf("access role %q has no deployed operations or distributions", roleName)
	}
	return auth.PolicySelector{Service: service.FullPath, Role: role.URI, Resources: resources}, nil
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
