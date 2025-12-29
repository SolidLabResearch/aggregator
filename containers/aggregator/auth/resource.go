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

func RegisterResource(resourceId string, issuer string, scopes []model.Scope) error {
	logrus.Infof("Registering resource %s with scopes %v", resourceId, scopes)
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

	logrus.Infof("Resource %s registered successfully", resourceId)
	return nil
}
