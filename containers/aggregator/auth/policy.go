package auth

import (
	"aggregator/model"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

func DefinePolicy(resourceId string, userId string, issuer string, scopes []model.Scope, namespace string) error {
	if issuer == "" {
		logrus.Debugf("Skipping policy creation for %s (no issuer)", resourceId)
		return nil
	}
	if !shouldCreatePolicies() {
		logrus.Debugf("Skipping policy creation for %s (registration/UMA policy disabled)", resourceId)
		return nil
	}

	resolvedUserID := strings.TrimSpace(userId)
	if resolvedUserID == "" {
		return fmt.Errorf("user ID is required to create provision policies")
	}

	body := map[string]interface{}{
		"issuer":      issuer,
		"resource_id": resourceId,
		"scopes":      scopes,
	}
	if resolvedUserID != "" {
		body["user_id"] = resolvedUserID
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	logrus.Debugf("Creating policy for resource %s with body: %s", resourceId, string(jsonBody))
	req, err := http.NewRequest(
		http.MethodPost,
		"http://ingress-uma.aggregator-app.svc.cluster.local/policies",
		bytes.NewReader(jsonBody),
	)
	if err != nil {
		return fmt.Errorf("failed to create policy request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// TODO: Replace WebID auth when the UMA server supports stronger credentials.
	authWebID := resolvedUserID
	if strings.EqualFold(os.Getenv("REGISTRATION_TYPE"), "provision") {
		if provisionWebID := strings.TrimSpace(os.Getenv("PROVISION_WEBID")); provisionWebID != "" {
			authWebID = provisionWebID
		}
	}
	req.Header.Set("Authorization", "WebID "+url.QueryEscape(authWebID))

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
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
func shouldCreatePolicies() bool {
	registrationType := strings.TrimSpace(os.Getenv("REGISTRATION_TYPE"))
	return strings.EqualFold(registrationType, "provision")
}
