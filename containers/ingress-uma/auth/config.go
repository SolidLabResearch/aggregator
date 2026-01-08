package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type UmaConfig struct {
	Issuer                       string `json:"issuer"`
	JwksUri                      string `json:"jwks_uri"`
	PermissionEndpoint           string `json:"permission_endpoint"`
	IntrospectionEndpoint        string `json:"introspection_endpoint"`
	ResourceRegistrationEndpoint string `json:"resource_registration_endpoint"`
	RegistrationEndpoint         string `json:"registration_endpoint"`
	TokenEndpoint                string `json:"token_endpoint"`
}

var requiredFields = map[string]func(UmaConfig) string{
	"issuer":                         func(c UmaConfig) string { return c.Issuer },
	"jwks_uri":                       func(c UmaConfig) string { return c.JwksUri },
	"permission_endpoint":            func(c UmaConfig) string { return c.PermissionEndpoint },
	"introspection_endpoint":         func(c UmaConfig) string { return c.IntrospectionEndpoint },
	"resource_registration_endpoint": func(c UmaConfig) string { return c.ResourceRegistrationEndpoint },
	"registration_endpoint":          func(c UmaConfig) string { return c.RegistrationEndpoint },
	"token_endpoint":                 func(c UmaConfig) string { return c.TokenEndpoint },
}

func fetchUmaConfig(issuer string) (UmaConfig, error) {
	url := fmt.Sprintf("%s/.well-known/uma2-configuration", issuer)

	resp, err := http.Get(url)
	if err != nil {
		return UmaConfig{}, fmt.Errorf("failed GET on UMA config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return UmaConfig{}, fmt.Errorf("UMA configuration request failed with status %d at %s", resp.StatusCode, url)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return UmaConfig{}, err
	}

	var cfg UmaConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		return UmaConfig{}, fmt.Errorf("invalid UMA configuration JSON: %w", err)
	}

	for key, getter := range requiredFields {
		if getter(cfg) == "" {
			return UmaConfig{}, fmt.Errorf("missing required UMA metadata field: %s", key)
		}
	}

	return cfg, nil
}
