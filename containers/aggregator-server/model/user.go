package model

import (
	"fmt"
	"time"
)

// AggregatorInstance represents a deployed aggregator for a user
type AggregatorInstance struct {
	AggregatorID        string
	OwnerWebID          string
	RegistrationType    string
	AuthorizationServer string
	Namespace           string
	BaseURL             string

	// Stored tokens (NEVER returned to client)
	AccessToken  string
	RefreshToken string

	CreatedAt time.Time
	UpdatedAt time.Time
}

// User represents a user with their aggregator instances
type User struct {
	UserId         string
	AccessToken    string
	RefreshToken   string
	AuthzServerURL string
	Namespace      string
}

func (u *User) ConfigEndpoints() map[string]string {
	return map[string]string{
		"actors": fmt.Sprintf("http://%s/config/%s/actors", ExternalHost, u.Namespace),
	}
}

// GetAggregatorURL returns the base URL for an aggregator instance
func GetAggregatorURL(aggregatorID string) string {
	return fmt.Sprintf("%s://%s/aggregators/%s/", Protocol, ExternalHost, aggregatorID)
}
