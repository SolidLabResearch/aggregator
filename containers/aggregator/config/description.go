package config

import (
	"aggregator/auth"
	"aggregator/model"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

func InitAggregatorDescription(mux *http.ServeMux, user model.User) error {
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleAggregatorDescription(w, r, user)
	})

	fullURL := fmt.Sprintf("%s://%s/config/%s", model.Protocol, model.ExternalHost, user.Namespace)
	if err := auth.RegisterResource(fullURL, user.AuthzServerURL, []model.Scope{model.Read}); err != nil {
		return fmt.Errorf("failed to register aggregator description %s: %w", fullURL, err)
	}
	if err := auth.DefinePolicy(fullURL, user.UserId, user.AuthzServerURL, []model.Scope{model.Read}); err != nil {
		return fmt.Errorf("failed to define policy for aggregator description %s: %w", fullURL, err)
	}

	return nil
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

	tokenExpiry, err := fetchAccessTokenExpiry(user.Namespace)
	loginStatus := false
	if err == nil && tokenExpiry != "" {
		parsed, parseErr := time.Parse(time.RFC3339, tokenExpiry)
		if parseErr == nil {
			loginStatus = time.Now().Before(parsed)
		}
	}

	// TODO: semantic representations need to be added at some point
	desc := AggregatorDescription{
		ID:                    fmt.Sprintf("%s://%s/config/%s", model.Protocol, model.ExternalHost, user.Namespace),
		CreatedAt:             time.Now().Format(time.RFC3339), // Placeholder, should be persisted
		LoginStatus:           loginStatus,
		TokenExpiry:           tokenExpiry,
		TransformationCatalog: fmt.Sprintf("%s://%s/config/%s/transformations", model.Protocol, model.ExternalHost, user.Namespace),
		ServiceCollection:     fmt.Sprintf("%s://%s/config/%s/services", model.Protocol, model.ExternalHost, user.Namespace),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(desc); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func fetchAccessTokenExpiry(namespace string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cm, err := model.Clientset.CoreV1().ConfigMaps(namespace).Get(ctx, "aggregator-instance-config", metav1.GetOptions{})
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(cm.Data["access_token_expiry"]), nil
}
