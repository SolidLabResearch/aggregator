package oidc

import (
	"aggregator/model"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// FetchOIDCConfig fetches and parses the OIDC discovery document for the given IdP
func FetchOIDCConfig(ctx context.Context, idpURL string) (*model.OIDCConfig, error) {
	discoveryURL := fmt.Sprintf("%s/.well-known/openid-configuration", idpURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build OIDC discovery request: %w", err)
	}

	res, err := model.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OIDC discovery document: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OIDC discovery returned non-OK status: %s", res.Status)
	}

	var cfg model.OIDCConfig
	if err := json.NewDecoder(res.Body).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("failed to decode OIDC discovery JSON: %w", err)
	}

	if cfg.AuthorizationEndpoint == "" || cfg.TokenEndpoint == "" {
		return nil, fmt.Errorf("OIDC config missing required endpoints")
	}

	return &cfg, nil
}
