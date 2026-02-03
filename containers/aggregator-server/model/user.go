package model

import (
	"fmt"
	"time"
)

// AggregatorInstance represents a deployed aggregator for a user
type AggregatorInstance struct {
	AggregatorID        string
	OwnerID             string
	RegistrationType    string
	AuthorizationServer string
	Namespace           string
	BaseURL             string

	// Stored tokens (NEVER returned to client)
	IDToken      string
	AccessToken  string
	RefreshToken string

	CreatedAt time.Time
	UpdatedAt time.Time
}

// GetAggregatorURL returns the aggregator description URL for a namespace.
func GetAggregatorURL(namespace string) string {
	return fmt.Sprintf("%s://%s/config/%s", Protocol, ExternalHost, namespace)
}
