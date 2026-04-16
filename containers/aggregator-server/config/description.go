package config

import (
	"aggregator/model"
	"encoding/json"
	"fmt"
	"net/http"
)

// AggregatorServerDescription represents the server description
type AggregatorServerDescription struct {
	RegistrationEndpoint       string   `json:"registration_endpoint"`
	SupportedRegistrationTypes []string `json:"supported_registration_types"`
	Version                    string   `json:"version"`
	ClientIdentifier           string   `json:"client_identifier,omitempty"`
	TransformationCatalog      string   `json:"transformation_catalog"`
}

func InitServerDescription(mux *http.ServeMux) {
	mux.HandleFunc("/", handleServerDescription)
}

func handleServerDescription(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// TODO: semantic representations need to be added at some point
	supported := model.AllowedRegistrationTypes

	desc := AggregatorServerDescription{
		RegistrationEndpoint:       fmt.Sprintf("%s%s", model.ExternalURL(), model.RegistrationEndpoint),
		SupportedRegistrationTypes: supported,
		Version:                    "1.0.0",
		ClientIdentifier:           model.SolidClientId,
		TransformationCatalog:      fmt.Sprintf("%s%s", model.ExternalURL(), model.TransformationCatalog),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(desc); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
