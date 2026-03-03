package config

import (
	"aggregator/auth"
	"aggregator/model"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// AggregatorDescription represents the aggregator instance description
type AggregatorDescription struct {
	ID                    string `json:"id,omitempty"`
	CreatedAt             string `json:"created_at"`
	LoginStatus           bool   `json:"login_status"`
	TransformationCatalog string `json:"transformation_catalog"`
	ServiceCollection     string `json:"service_collection"`
}

func InitAggregatorDescription(mux *http.ServeMux) error {
	if err := auth.RegisterResource(model.ExternalBaseURL(), []model.Scope{model.Read}); err != nil {
		return fmt.Errorf("failed to register resource %s: %w", model.ExternalBaseURL(), err)
	}
	if err := auth.DefinePolicy(model.ExternalBaseURL(), []model.Scope{model.Read}); err != nil {
		return fmt.Errorf("failed to define policy for resource %s: %w", model.ExternalBaseURL(), err)
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

	loginStatus := checkLoginStatus()

	createdAt, err := fetchCreatedAt()
	if err != nil || createdAt == "" {
		createdAt = time.Now().Format(time.RFC3339)
	}

	// TODO: semantic representations need to be added at some point
	desc := AggregatorDescription{
		ID:                    model.ExternalBaseURL(),
		CreatedAt:             createdAt,
		LoginStatus:           loginStatus,
		TransformationCatalog: model.ExternalBaseURL() + model.TransformationCatalog,
		ServiceCollection:     model.ExternalBaseURL() + model.ServiceCollection,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(desc); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func checkLoginStatus() bool {
	// URL-encode the userID for safe use as a query parameter
	encodedID := url.QueryEscape(model.Owner.UserId)

	url := fmt.Sprintf(
		"http://token-service.%s.svc.cluster.local:8080/loginstatus?id=%s",
		model.Namespace,
		encodedID,
	)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		logrus.WithError(err).Debug("Failed to create login status check request")
		return false
	}

	resp, err := model.HttpClient.Do(req)
	if err != nil {
		logrus.WithError(err).Debug("Failed to check login status")
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logrus.WithField("status_code", resp.StatusCode).
			Debug("Login status check returned non-OK status")
		return false
	}

	var result struct {
		LoginStatus bool `json:"login_status"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		logrus.WithError(err).Debug("Failed to decode login status response")
		return false
	}

	return result.LoginStatus
}

// fetchCreatedAt reads the "created_at" key from the mounted ConfigMap
func fetchCreatedAt() (string, error) {
	data, err := os.ReadFile("/etc/config/created_at")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
