package model

// OIDCConfig represents the relevant fields from the OpenID configuration
type OIDCConfig struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
}

// RegistrationRequest represents the request body for the registration endpoint
type RegistrationRequest struct {
	// REQUIRED for all flows
	RegistrationType string `json:"registration_type"`

	// OPTIONAL - for updating existing aggregator
	AggregatorID string `json:"aggregator_id,omitempty"`

	// REQUIRED for authorization_code and client_credentials flows
	AuthorizationServer string `json:"authorization_server,omitempty"`

	// authorization_code flow - finish phase
	Code        string `json:"code,omitempty"`
	RedirectURI string `json:"redirect_uri,omitempty"`
	State       string `json:"state,omitempty"`

	// client_credentials flow
	WebID        string `json:"webid,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`

	// Internal fields (not from JSON)
	OIDCConfig   OIDCConfig `json:"-"`
	CodeVerifier string     `json:"-"`
}

// RegistrationResponse represents the response for successful aggregator creation/update
type RegistrationResponse struct {
	AggregatorID string `json:"aggregator_id"`
	Aggregator   string `json:"aggregator,omitempty"`
	WebID        string `json:"webid,omitempty"`
}

// AuthorizationCodeStartResponse represents the response for authorization_code start phase
type AuthorizationCodeStartResponse struct {
	AggregatorClientID  string `json:"aggregator_client_id"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	State               string `json:"state"`
}
