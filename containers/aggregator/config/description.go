package config

import (
	"aggregator/auth"
	"aggregator/model"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// AggregatorDescription represents the aggregator instance description
type AggregatorDescription struct {
	ID                    string `json:"id,omitempty"`
	CreatedAt             string `json:"created_at"`
	LoginStatus           bool   `json:"login_status"`
	TokenExpiry           string `json:"token_expiry,omitempty"`
	TransformationCatalog string `json:"transformation_catalog"`
	ServiceCollection     string `json:"service_collection"`
}

func InitAggregatorDescription(mux *http.ServeMux) error {
	if err := auth.RegisterResource(model.BaseUrl, model.Owner.AuthzServerURL, []model.Scope{model.Read}); err != nil {
		return fmt.Errorf("failed to register resource %s: %w", model.BaseUrl, err)
	}
	if err := auth.DefinePolicy(model.BaseUrl, model.Owner.UserId, model.Owner.AuthzServerURL, []model.Scope{model.Read}); err != nil {
		return fmt.Errorf("failed to define policy for resource %s: %w", model.BaseUrl, err)
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleAggregatorDescription(w, r)
	})

	return nil
}

func handleAggregatorDescription(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tokenExpiry, err := fetchAccessTokenExpiry()
	loginStatus := false
	if err == nil && tokenExpiry != "" {
		parsed, parseErr := time.Parse(time.RFC3339, tokenExpiry)
		if parseErr == nil {
			loginStatus = time.Now().Before(parsed)
		}
	}

	createdAt, err := fetchCreatedAt()
	if err != nil || createdAt == "" {
		createdAt = time.Now().Format(time.RFC3339)
	}

	// TODO: semantic representations need to be added at some point
	desc := AggregatorDescription{
		ID:                    model.BaseUrl,
		CreatedAt:             createdAt,
		LoginStatus:           loginStatus,
		TokenExpiry:           tokenExpiry,
		TransformationCatalog: model.BaseUrl + model.TransformationCatalog,
		ServiceCollection:     model.BaseUrl + model.ServiceCollection,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(desc); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// fetchAccessTokenExpiry reads the "access_token_expiry" key from the mounted ConfigMap
func fetchAccessTokenExpiry() (string, error) {
	data, err := os.ReadFile("/etc/config/access_token_expiry")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// fetchCreatedAt reads the "created_at" key from the mounted ConfigMap
func fetchCreatedAt() (string, error) {
	data, err := os.ReadFile("/etc/config/created_at")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
