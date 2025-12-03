package types

type RegistrationRequest struct {
	AuthzServerURL  string `json:"as_url"`
	UserIdp         string `json:"openid_provider"`
	SuccessRedirect string `json:"success_redirect"`
	FailRedirect    string `json:"fail_redirect"`
}
