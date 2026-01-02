package auth

import (
	"aggregator/model"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/sirupsen/logrus"
)

func DefinePolicy(resourceId string, userId string, issuer string, scopes []model.Scope) error {
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

	logrus.Debugf("Creating policy for resource %s with body: %s", resourceId, string(jsonBody))
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

	logrus.Infof("Policy created successfully for resource %s", resourceId)
	return nil
}
