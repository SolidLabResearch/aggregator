package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"ingress-uma/model"
	"io"
	"net/http"

	"github.com/sirupsen/logrus"
)

type ResourceData struct {
	UmaID  string
	UserID string
}

var idIndex = make(map[string]ResourceData)
var asIndex = make(map[string]string)

func HandleResourceRequest(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		handlePostResource(w, r)
	case http.MethodDelete:
		handleDeleteResource(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handlePostResource(w http.ResponseWriter, r *http.Request) {
	var reqData struct {
		UserID     string   `json:"user_id"`
		ASUrl      string   `json:"as_url"`
		ResourceID string   `json:"resource_id"`
		Scopes     []string `json:"scopes"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqData); err != nil {
		logrus.WithError(err).Warn("Invalid JSON in request body")
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Basic validation
	if reqData.UserID == "" || reqData.ASUrl == "" || reqData.ResourceID == "" || len(reqData.Scopes) == 0 {
		http.Error(w, "Missing required fields: user_id, as_url, resource_id, scopes", http.StatusBadRequest)
		return
	}

	scopes := stringsToScopes(reqData.Scopes)

	logrus.WithFields(logrus.Fields{
		"user_id":     reqData.UserID,
		"as_url":      reqData.ASUrl,
		"resource_id": reqData.ResourceID,
		"scopes":      reqData.Scopes,
	}).Info("Received resource registration request")

	reg := Registration{
		UserID:      reqData.UserID,
		AuthzServer: reqData.ASUrl,
	}
	if err := createResource(reg, reqData.ResourceID, scopes); err != nil {
		logrus.WithError(err).Error("Failed to create UMA resource")
		http.Error(w, "Failed to register resource", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func createResource(reg Registration, resourceId string, scopes []Scope) error {
	// Fetch UMA configuration
	config, err := fetchUmaConfig(reg.AuthzServer)
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("Error while retrieving UMA configuration")
		return err
	}

	// Check if resource already registered
	data, update := idIndex[resourceId]
	endpoint := config.ResourceRegistrationEndpoint
	method := "POST"
	if update {
		endpoint = endpoint + "/" + data.UmaID
		method = "PUT"
	}

	// Generate resource description with name and resource_scopes
	scopeStrings := make([]string, len(scopes))
	for i, scope := range scopes {
		scopeStrings[i] = string(scope)
	}

	description := map[string]interface{}{
		"name":            resourceId,
		"resource_scopes": scopeStrings,
	}

	jsonData, err := json.Marshal(description)
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err, "resource_id": resourceId}).Error("Error while marshaling resource description")
		return err
	}

	req, err := http.NewRequest(method, endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err, "resource_id": resourceId}).Error("Error while creating UMA request")
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	pat, err := getPAT(reg)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+pat)

	action := "Creating"
	if update {
		action = "Updating"
	}
	logrus.WithFields(logrus.Fields{"action": action, "resource_id": resourceId, "endpoint": endpoint}).Info("Processing UMA resource registration")

	res, err := model.HttpClient.Do(req)
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err, "resource_id": resourceId, "endpoint": endpoint}).Error("Error while making UMA request")
		return err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err, "status": res.Status, "resource_id": resourceId}).Error("Error while reading UMA response body")
		return err
	}

	if update {
		if res.StatusCode != http.StatusOK {
			logrus.WithFields(logrus.Fields{"status": res.Status, "body": string(body), "resource_id": resourceId}).Error("Resource update request failed")
			return nil
		}
	} else {
		if res.StatusCode != http.StatusCreated {
			logrus.WithFields(logrus.Fields{"status": res.Status, "body": string(body), "resource_id": resourceId}).Error("Resource registration request failed")
			return nil
		}
		var responseData struct {
			ID string `json:"_id"`
		}
		if err := json.Unmarshal(body, &responseData); err != nil {
			logrus.WithFields(logrus.Fields{"err": err, "resource_id": resourceId}).Error("Error while parsing UMA response JSON")
			return err
		}
		if responseData.ID == "" {
			logrus.WithFields(logrus.Fields{"resource_id": resourceId}).Warn("Unexpected UMA response; no UMA id received")
			return nil
		}
		idIndex[resourceId] = ResourceData{UmaID: responseData.ID, UserID: reg.UserID}
		asIndex[resourceId] = reg.AuthzServer
		logrus.WithFields(logrus.Fields{"resource_id": resourceId, "uma_id": responseData.ID}).Info("Registered resource with UMA")
	}
	return nil
}

// handleDeleteResource handles DELETE /resource requests
func handleDeleteResource(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var reqData struct {
		ResourceID string `json:"resource_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqData); err != nil {
		logrus.WithError(err).Warn("Invalid JSON in request body")
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if reqData.ResourceID == "" {
		http.Error(w, "Missing required fields: user_id, as_url, resource_id", http.StatusBadRequest)
		return
	}

	logrus.WithFields(logrus.Fields{
		"resource_id": reqData.ResourceID,
	}).Info("Received resource deletion request")

	if err := deleteResource(reqData.ResourceID); err != nil {
		logrus.WithError(err).Debug("Failed to delete UMA resource")
		http.Error(w, fmt.Sprintf("Failed to delete resource: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// deleteResource deletes a single resource from the authorization server and updates local state
func deleteResource(resourceId string) error {
	data, ok := idIndex[resourceId]
	if !ok {
		// Resource not registered / already deleted
		return fmt.Errorf("resource %s not found locally", resourceId)
	}
	asUrl, ok := asIndex[resourceId]
	if !ok {
		// Resource not registered at authz server
		return fmt.Errorf("resource %s not registered at authz server", resourceId)
	}

	config, err := fetchUmaConfig(asUrl)
	if err != nil {
		return fmt.Errorf("failed to fetch UMA config: %w", err)
	}

	deleteURL := fmt.Sprintf("%s%s", config.ResourceRegistrationEndpoint, data.UmaID)

	req, err := http.NewRequest("DELETE", deleteURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create DELETE request for resource %s: %w", resourceId, err)
	}

	// Set headers
	reg := Registration{
		UserID:      data.UserID,
		AuthzServer: asUrl,
	}
	req.Header.Set("Accept", "application/json")
	pat, err := getPAT(reg)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+pat)

	res, err := model.HttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send signed DELETE request for resource %s: %w", resourceId, err)
	}
	defer res.Body.Close()

	// Successful deletion
	if res.StatusCode == http.StatusOK || res.StatusCode == http.StatusNoContent || res.StatusCode == http.StatusResetContent {
		// Remove local references
		delete(idIndex, resourceId)
		delete(asIndex, resourceId)
		logrus.WithFields(logrus.Fields{
			"resource": resourceId,
			"uma_id":   data.UmaID,
		}).Info("Deleted UMA resource successfully")
		return nil
	}

	// Conflict due to non-empty collections
	if res.StatusCode == http.StatusConflict {
		body, _ := io.ReadAll(res.Body)
		logrus.WithFields(logrus.Fields{
			"resource": resourceId,
			"uma_id":   data.UmaID,
			"status":   res.Status,
			"body":     string(body),
		}).Debug("Failed to delete UMA resource: non-empty collections")
		return fmt.Errorf("resource %s deletion blocked: non-empty collections", resourceId)
	}

	// Unexpected status
	body, _ := io.ReadAll(res.Body)
	return fmt.Errorf("unexpected status deleting resource %s: %s - %s", resourceId, res.Status, string(body))
}

// DeleteResources deletes all locally stored resources concurrently
func DeleteResources() error {
	type deletionResult struct {
		resourceID string
		err        error
	}

	results := make(chan deletionResult)
	concurrency := 5 // adjust concurrency as needed
	sem := make(chan struct{}, concurrency)

	// Launch deletion goroutines
	for resourceID, asUrl := range asIndex {
		sem <- struct{}{} // acquire semaphore
		go func(res, asUrl string) {
			defer func() { <-sem }() // release semaphore
			err := deleteResource(resourceID)
			results <- deletionResult{resourceID: res, err: err}
		}(resourceID, asUrl)
	}

	// Collect results
	var errs []error
	for i := 0; i < len(asIndex); i++ {
		r := <-results
		if r.err != nil {
			logrus.WithFields(logrus.Fields{
				"resource": r.resourceID,
			}).Debugf("Failed to delete resource: %v", r.err)
			errs = append(errs, r.err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to delete %d resources; see debug logs for details", len(errs))
	}
	return nil
}
