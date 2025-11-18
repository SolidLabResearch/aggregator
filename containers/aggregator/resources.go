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
	Append Scope = "urn:example:css:modes:append"
	Create Scope = "urn:example:css:modes:create"
	Delete Scope = "urn:example:css:modes:delete"
	Write  Scope = "urn:example:css:modes:write"
)

func registerResource(id, issuer string) error {
	body := map[string]interface{}{
		"issuer":      issuer,
		"resource_id": id,
		"scopes":      []Scope{Read},
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
		return fmt.Errorf("failed to register resource %q: %w", id, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("resource registration failed: status=%d, body=%s", resp.StatusCode, string(respBody))
	}

	return nil
}
