package config

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"aggregator/model"

	"github.com/sirupsen/logrus"
)

const ingressUMADerivedResourceEndpoint = "http://ingress-uma.aggregator-app.svc.cluster.local/derived-resources"

type derivedSource struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

type derivedResourceRequest struct {
	Location          string         `json:"location"`
	Sources           []derivedSource `json:"sources"`
}

func InitDerivedResourceRelay(mux *http.ServeMux, user model.User) {
	mux.HandleFunc("/derived-resources", func(w http.ResponseWriter, r *http.Request) {
		handleDerivedResourceRelay(w, r, user)
	})
}

// TODO: switch from the WebID scheme to Bearer tokens
func handleDerivedResourceRelay(w http.ResponseWriter, r *http.Request, user model.User) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var reqData derivedResourceRequest
	if err := json.NewDecoder(r.Body).Decode(&reqData); err != nil {
		logrus.WithError(err).Warn("Invalid JSON in derived resource relay body")
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if strings.TrimSpace(reqData.Location) == "" {
		http.Error(w, "Missing required fields: location", http.StatusBadRequest)
		return
	}
	if len(reqData.Sources) == 0 {
		http.Error(w, "Missing required fields: sources", http.StatusBadRequest)
		return
	}

	ownerWebID := policyOwnerWebID(user.UserId)
	if ownerWebID == "" {
		http.Error(w, "Unable to determine policy owner", http.StatusInternalServerError)
		return
	}

	payload, err := json.Marshal(reqData)
	if err != nil {
		http.Error(w, "Failed to encode relay request", http.StatusInternalServerError)
		return
	}

	req, err := http.NewRequest(http.MethodPost, ingressUMADerivedResourceEndpoint, bytes.NewReader(payload))
	if err != nil {
		http.Error(w, "Failed to build relay request", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "WebID "+url.QueryEscape(ownerWebID))

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logrus.WithError(err).Error("Failed to relay derived resource request")
		http.Error(w, "Failed to relay derived resource request", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		logrus.WithFields(logrus.Fields{
			"status": resp.StatusCode,
			"body":   string(bodyBytes),
		}).Error("Derived resource relay failed")
		http.Error(w, "Failed to relay derived resource request", http.StatusBadGateway)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func policyOwnerWebID(fallback string) string {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("REGISTRATION_TYPE")), "provision") {
		if provisionWebID := strings.TrimSpace(os.Getenv("PROVISION_WEBID")); provisionWebID != "" {
			return provisionWebID
		}
	}
	return strings.TrimSpace(fallback)
}
