package config

import (
	"aggregator/auth"
	"aggregator/model"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

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
