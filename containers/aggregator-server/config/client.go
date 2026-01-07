package config

import (
	"aggregator/model"
	"encoding/json"
	"github.com/sirupsen/logrus"
	"net/http"
)

type ClientIdentifierDocument struct {
	Context  []string `json:"@context,omitempty"`
	ClientID string   `json:"client_id"`
}

var (
	clientIdentifierJSON   []byte
	clientIdentifierJSONLD []byte
)

func InitClientIdentifier(mux *http.ServeMux) {
	logrus.Info("Initializing client identifier endpoint")

	var err error

	// Pre-encode JSON-LD version (with context)
	clientDocLD := ClientIdentifierDocument{
		Context:  []string{"https://www.w3.org/ns/solid/oidc-context.jsonld"},
		ClientID: model.ClientId,
	}
	clientIdentifierJSONLD, err = json.Marshal(clientDocLD)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to marshal client identifier JSON-LD document")
	}

	// Pre-encode JSON version (without context)
	clientDocJSON := ClientIdentifierDocument{
		ClientID: model.ClientId,
	}
	clientIdentifierJSON, err = json.Marshal(clientDocJSON)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to marshal client identifier JSON document")
	}

	mux.HandleFunc("/client.json", handleClientIdentifier)
	logrus.Info("Client identifier endpoint initialization completed")
}

func handleClientIdentifier(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	accept := r.Header.Get("Accept")

	var contentType string
	var body []byte

	preferredType := negotiateContentType(accept, []string{"application/ld+json", "application/json"})

	if preferredType == "application/json" {
		contentType = "application/json"
		body = clientIdentifierJSON
	} else {
		contentType = "application/ld+json"
		body = clientIdentifierJSONLD
	}

	w.Header().Set("Content-Type", contentType)

	if r.Method == http.MethodHead {
		return
	}

	if _, err := w.Write(body); err != nil {
		logrus.WithError(err).Error("Failed to write client identifier document")
	}
}
