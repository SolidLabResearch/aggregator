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
	ClientIdentifier           string   `json:"client_identifier"`
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
	// TODO: make the SupportedRegistrationTypes configurable
	desc := AggregatorServerDescription{
		RegistrationEndpoint: fmt.Sprintf("%s://%s/registration", model.Protocol, model.ExternalHost),
		SupportedRegistrationTypes: []string{
			"authorization_code",
		},
		Version:               "1.0.0",
		ClientIdentifier:      fmt.Sprintf("%s://%s/client.json", model.Protocol, model.ExternalHost), // Placeholder, not implemented yet
		TransformationCatalog: fmt.Sprintf("%s://%s/config/transformations", model.Protocol, model.ExternalHost),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(desc); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
