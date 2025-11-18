package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"ingress-uma/signing"
	"io"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
)

type Permission struct {
	UmaId          string  `json:"resource_id"`
	ResourceScopes []Scope `json:"resource_scopes"`
}

var ExternalHost string

func InitAuth(extHost string) {
	ExternalHost = extHost
}

func AuthorizeRequest(w http.ResponseWriter, r *http.Request) {
	// Extract the UMA information from the forwarded headers
	scheme := strings.Trim(r.Header.Get("X-Forwarded-Proto"), "[]")

	resourcePath := strings.Trim(r.Header.Get("X-Forwarded-Uri"), "[]")
	resourceId := fmt.Sprintf("%s://%s%s", scheme, ExternalHost, resourcePath)
	umaId := idIndex[resourceId]
	if umaId == "" {
		logrus.WithFields(logrus.Fields{"resource": resourceId}).Warn("No UMA id found for resource")
		http.Error(w, "No UMA id found for resource", http.StatusUnauthorized)
		return
	}

	issuer := issuerIndex[resourceId]
	if issuer == "" {
		logrus.Warn("No Authentication Server Url found for resource")
		http.Error(w, "No Authentication Server Url found for resource", http.StatusUnauthorized)
		return
	}

	logrus.WithFields(logrus.Fields{"resource": resourceId, "uma_id": umaId, "as_url": issuer}).Info("Authorize request")

	// No ticket
	if r.Header.Get("Authorization") == "" {
		permissions := make(map[string][]Scope)
		scopes, err := determineScopes(r.Method)
		if err != nil {
			logrus.WithError(err).Error("Error determining scopes")
			http.Error(w, "Error determining scopes", http.StatusUnauthorized)
			return
		}
		permissions[umaId] = scopes

		ticket, err := fetchTicket(issuer, permissions)
		if err != nil {
			logrus.WithError(err).Error("Error while fetching ticket")
			http.Error(w, "Error while fetching ticket", http.StatusUnauthorized)
			return
		}

		// no ticket needed
		if ticket == "" {
			logrus.Info("✅ No ticket needed - access granted immediately")
			w.WriteHeader(http.StatusOK)
			return
		}

		// return ticket with WWW-Authenticate header
		logrus.Info("🎫 Ticket created successfully, sending WWW-Authenticate header")
		w.Header().Set(
			"WWW-Authenticate",
			fmt.Sprintf(`UMA as_uri="%s", ticket="%s"`, issuer, ticket),
		)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusUnauthorized)
}

func determineScopes(method string) ([]Scope, error) {
	switch method {
	case "POST", "PUT", "DELETE":
		logrus.WithFields(logrus.Fields{"method": method}).Debug("🔧 Requesting 'modify' permissions")
		return []Scope{Modify}, nil
	case "GET":
		logrus.WithFields(logrus.Fields{"method": method}).Debug("📖 Requesting 'read' permissions")
		return []Scope{Read}, nil
	default:
		logrus.WithFields(logrus.Fields{"method": method}).Warn("❌ Method not supported by authorization")
		return nil, fmt.Errorf("❌ Method %s not supported by authorization", method)
	}
}

func fetchTicket(asUrl string, permissions map[string][]Scope) (string, error) {
	config, err := fetchUmaConfig(asUrl)
	if err != nil {
		return "", fmt.Errorf("error while retrieving config: %w", err)
	}

	// Create body with permissions
	body := []Permission{}
	for id, scopes := range permissions {
		body = append(body, Permission{
			UmaId:          id,
			ResourceScopes: scopes,
		})
	}

	jsonData, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("error while constructing body: %w", err)
	}

	// Request ticket
	req, err := http.NewRequest("POST", config.PermissionEndpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := signing.DoSignedRequest(req)
	if err != nil {
		return "", fmt.Errorf("error while signing ticket request: %w", err)
	}
	defer resp.Body.Close()
	logrus.WithFields(logrus.Fields{"status_code": resp.StatusCode}).Debug("Permission endpoint response status")

	// No ticket needed
	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("error while parsing response body with statuscode %d: %w", resp.StatusCode, err)
		}
		logrus.WithFields(logrus.Fields{"body": string(bodyBytes)}).Debug("Permission endpoint response body")
		return "", nil
	}

	// Failed to fetch ticket
	if resp.StatusCode != http.StatusCreated {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("error while parsing response body with statuscode %d: %w", resp.StatusCode, err)
		}
		bodyString := string(bodyBytes)
		return "", fmt.Errorf(
			"error while fetching ticket from %s: Status %d with message \"%s\"",
			config.PermissionEndpoint,
			resp.StatusCode,
			bodyString,
		)
	}

	var jsonResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&jsonResponse); err != nil {
		return "", err
	}

	// Return ticket
	ticket, ok := jsonResponse["ticket"].(string)
	if !ok || ticket == "" {
		return "", fmt.Errorf("invalid response from persmission endpoint %s: No ticket in response", config.PermissionEndpoint)
	}

	return ticket, nil
}
