package config

import (
	"aggregator/model"
	"encoding/json"
	"net/http"

	"github.com/sirupsen/logrus"
)

type ClientIdentifierDocument struct {
	Context  []string `json:"@context,omitempty"`
	ClientID string   `json:"client_id"`
}

var clientIdentifierJSONLD []byte

func InitClientIdentifier(mux *http.ServeMux) {
	logrus.Info("Initializing client identifier endpoint")
	model.SolidClientId = model.ExternalURL() + "/client.jsonld"

	var err error

	// Pre-encode JSON-LD version (with context)
	clientDocLD := ClientIdentifierDocument{
		Context:  []string{"https://www.w3.org/ns/solid/oidc-context.jsonld"},
		ClientID: model.SolidClientId,
	}
	clientIdentifierJSONLD, err = json.Marshal(clientDocLD)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to marshal client identifier JSON-LD document")
	}

	mux.HandleFunc("/client.jsonld", handleClientIdentifier)
	logrus.Info("Client identifier endpoint initialization completed")
}

func handleClientIdentifier(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/ld+json")

	if r.Method == http.MethodHead {
		return
	}

	if _, err := w.Write(clientIdentifierJSONLD); err != nil {
		logrus.WithError(err).Error("Failed to write client identifier document")
	}
}
