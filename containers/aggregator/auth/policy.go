package auth

import (
	"aggregator/model"
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/sirupsen/logrus"
)

func DefinePolicy(resourceId string, scopes []model.Scope) error {
	if model.Owner.AuthzServerURL == "" {
		logrus.Debugf("Skipping policy creation for %s (no issuer)", resourceId)
		return nil
	}

	body := map[string]interface{}{
		"as_url":      model.Owner.AuthzServerURL,
		"resource_id": resourceId,
		"scopes":      scopes,
		"assignee":    model.Owner.UserId,
		"assigner":    model.Owner.UserId,
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	logrus.Debugf("Creating policy for resource %s with body: %s", resourceId, string(jsonBody))
	resp, err := model.HttpClient.Post(
		fmt.Sprintf("http://ingress-uma.%s.svc.cluster.local:8080/policies", model.Namespace),
		"application/json",
		bytes.NewReader(jsonBody),
	)
	if err != nil {
		return fmt.Errorf("failed to send policy request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("policy request failed: status=%d, body=%s", resp.StatusCode, string(respBody))
	}

	logrus.Infof("Policy created successfully for resource %s", resourceId)
	return nil
}
