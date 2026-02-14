package auth

import (
	"aggregator/model"
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/sirupsen/logrus"
)

func RegisterResource(resourceId string, scopes []model.Scope) error {
	if model.Owner.AuthzServerURL == "" {
		logrus.Debugf("Skipping resource registration for %s (no issuer)", resourceId)
		return nil
	}

	logrus.Infof("Registering resource %s with scopes %v", resourceId, scopes)
	body := map[string]interface{}{
		"aggregator_id": model.ID,
		"user_id":       model.Owner.UserId,
		"as_url":        model.Owner.AuthzServerURL,
		"resource_id":   resourceId,
		"scopes":        scopes,
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	resp, err := model.HttpClient.Post(
		fmt.Sprintf("http://ingress-uma.%s.svc.cluster.local:8080/resources", model.Namespace),
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

	logrus.Infof("Resource %s registered successfully", resourceId)
	return nil
}
