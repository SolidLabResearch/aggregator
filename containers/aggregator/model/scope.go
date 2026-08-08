package model

type Scope string

const (
	Read   Scope = "urn:example:css:modes:read"
	Create Scope = "urn:example:css:modes:create"
	Delete Scope = "urn:example:css:modes:delete"
	Write  Scope = "urn:example:css:modes:write"

	// Future semantic UMA scopes:
	// Execute Scope = "urn:example:css:modes:execute"
	// Modify  Scope = "urn:example:css:modes:modify"
)
