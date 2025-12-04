package model

// OIDCConfig represents the relevant fields from the OpenID configuration
type OIDCConfig struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

type RegistrationRequest struct {
	AuthzServerURL string     `json:"as_url"`
	UserIdp        string     `json:"openid_provider"`
	OIDCConfig     OIDCConfig `json:"oidc_config"`
}
