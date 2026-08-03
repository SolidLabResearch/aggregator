package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/sirupsen/logrus"
)

type derivedSource struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

type derivedResourceRequest struct {
	Location string          `json:"location"`
	Sources  []derivedSource `json:"sources"`
}

func HandleDerivedResourceRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var reqData derivedResourceRequest
	if err := json.NewDecoder(r.Body).Decode(&reqData); err != nil {
		logrus.WithError(err).Warn("Invalid JSON in derived resource request body")
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if strings.TrimSpace(reqData.Location) == "" {
		http.Error(w, "Missing required fields: location", http.StatusBadRequest)
		return
	}
	if len(reqData.Sources) == 0 {
		http.Error(w, "Missing required fields: sources", http.StatusBadRequest)
		return
	}

	resourceIDs := derivedResourceIDs(reqData.Location)
	if len(resourceIDs) == 0 {
		http.Error(w, "Invalid location", http.StatusBadRequest)
		return
	}

	owners := deriveOwnersFromSources(reqData.Sources)
	if len(owners) == 0 {
		http.Error(w, "Unable to derive resource owners", http.StatusBadRequest)
		return
	}

	for _, resourceID := range resourceIDs {
		resData := resourceIndex[resourceID]
		if resData.AggData.AuthzServer == "" {
			logrus.WithFields(logrus.Fields{"resource_id": resourceID}).Warn("No Authentication Server Url found for resource")
			continue
		}

		for owner := range owners {
			if err := createPolicy(resData.AggData.AuthzServer, resourceID, []Scope{Read}, owner, owner, []string{}); err != nil {
				logrus.WithFields(logrus.Fields{
					"resource_id": resourceID,
					"owner":       owner,
					"as_url":      resData.AggData.AuthzServer,
					"error":       err,
				}).Error("Failed to create policy for derived resource")
				http.Error(w, "Failed to create policy", http.StatusInternalServerError)
				return
			}
		}
	}

	logrus.WithFields(logrus.Fields{
		"location":  reqData.Location,
		"owners":    owners,
		"resources": resourceIDs,
	}).Info("Created policy for derived resource")

	w.WriteHeader(http.StatusCreated)
}

func resolveExternalResourceID(location string) string {
	trimmed := strings.TrimSpace(location)
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") {
		return trimmed
	}
	if !strings.HasPrefix(trimmed, "/") {
		trimmed = "/" + trimmed
	}
	return fmt.Sprintf("http://%s%s", ExternalHost, trimmed)
}

func derivedResourceIDs(location string) []string {
	resourceID := resolveExternalResourceID(location)
	if resourceID == "" {
		return nil
	}

	parsed, err := url.Parse(resourceID)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return []string{resourceID}
	}

	segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(segments) < 3 || segments[0] != "services" {
		return []string{resourceID}
	}

	namespace := segments[1]
	serviceID := segments[2]
	base := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
	unique := map[string]struct{}{}
	resourceIDs := []string{
		resourceID,
		fmt.Sprintf("%s/config/%s", base, namespace),
		fmt.Sprintf("%s/config/%s/services", base, namespace),
		fmt.Sprintf("%s/config/%s/deployments", base, namespace),
		fmt.Sprintf("%s/config/%s/services/%s", base, namespace, serviceID),
	}
	for _, entry := range resourceIDs {
		if entry == "" {
			continue
		}
		if _, exists := unique[entry]; exists {
			continue
		}
		unique[entry] = struct{}{}
	}

	deduped := make([]string, 0, len(unique))
	for entry := range unique {
		deduped = append(deduped, entry)
	}
	return deduped
}

func deriveOwnersFromSources(sources []derivedSource) map[string]struct{} {
	owners := make(map[string]struct{})
	for _, source := range sources {
		owner := deriveOwnerWebID(source.URL)
		if owner == "" {
			continue
		}
		owners[owner] = struct{}{}
	}
	return owners
}

func deriveOwnerWebID(sourceURL string) string {
	trimmed := strings.TrimSpace(sourceURL)
	if trimmed == "" {
		return ""
	}
	if strings.Contains(trimmed, "#me") {
		return trimmed
	}

	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}

	if strings.Contains(parsed.Path, "/profile/card") {
		base := strings.TrimSuffix(parsed.Path, "#me")
		if !strings.HasSuffix(base, "/card") && !strings.HasSuffix(base, "/profile/card") {
			base = path.Join(base, "profile", "card")
		}
		return fmt.Sprintf("%s://%s%s#me", parsed.Scheme, parsed.Host, base)
	}

	segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(segments) == 0 || segments[0] == "" {
		return ""
	}

	return fmt.Sprintf("%s://%s/%s/profile/card#me", parsed.Scheme, parsed.Host, segments[0])
}
