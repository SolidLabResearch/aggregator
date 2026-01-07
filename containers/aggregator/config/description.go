package config

import (
	"aggregator/model"
	"encoding/json"
	"fmt"
	"net/http"
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

func InitAggregatorDescription(mux *http.ServeMux, user model.User) {
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleAggregatorDescription(w, r, user)
	})
}

func handleAggregatorDescription(w http.ResponseWriter, r *http.Request, user model.User) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// TODO: semantic representations need to be added at some point
	// TODO: fetch actual login status and token expiry
	desc := AggregatorDescription{
		ID:                    fmt.Sprintf("%s://%s/", model.Protocol, model.ExternalHost),
		CreatedAt:             time.Now().Format(time.RFC3339), // Placeholder, should be persisted
		LoginStatus:           true,                            // Placeholder
		TransformationCatalog: fmt.Sprintf("%s://%s/transformations", model.Protocol, model.ExternalHost),
		ServiceCollection:     fmt.Sprintf("%s://%s/config/%s/actors", model.Protocol, model.ExternalHost, user.Namespace),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(desc); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
