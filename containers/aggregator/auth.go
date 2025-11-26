package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type Scope string

const (
	Read   Scope = "urn:example:css:modes:read"
	Create Scope = "urn:example:css:modes:create"
	Delete Scope = "urn:example:css:modes:delete"
	Write  Scope = "urn:example:css:modes:write"
)

func registerResource(resourceId string, issuer string, scopes []Scope) error {
	body := map[string]interface{}{
		"issuer":      issuer,
		"resource_id": resourceId,
		"scopes":      scopes,
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	resp, err := http.Post(
		"http://ingress-uma.aggregator-app.svc.cluster.local/resources",
		"application/json",
		bytes.NewReader(jsonBody),
	)
	if err != nil {
		return fmt.Errorf("failed to register public resource %q: %w", resourceId, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("resource registration failed: status=%d, body=%s", resp.StatusCode, string(respBody))
	}

	return nil
}

func definePublicPolicy(resourceId string, issuer string, scopes []Scope) error {
	return definePolicy(resourceId, "", issuer, scopes)
}

func definePolicy(resourceId string, userId string, issuer string, scopes []Scope) error {
	body := map[string]interface{}{
		"issuer":      issuer,
		"resource_id": resourceId,
		"scopes":      scopes,
	}
	if userId != "" {
		body["user_id"] = userId
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	resp, err := http.Post(
		"http://ingress-uma.aggregator-app.svc.cluster.local/policies",
		"application/json",
		bytes.NewReader(jsonBody),
	)
	if err != nil {
		return fmt.Errorf("failed to create a policy for resource %q: %w", resourceId, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("policy creation failed: status=%d, body=%s", resp.StatusCode, string(respBody))
	}

	return nil
}
