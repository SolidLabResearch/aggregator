package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"ingress-uma/signing"

	"github.com/sirupsen/logrus"
)

var idIndex = make(map[string]string)
var issuerIndex = make(map[string]string)

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
		Issuer     string   `json:"issuer"`
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
	if reqData.Issuer == "" || reqData.ResourceID == "" || len(reqData.Scopes) == 0 {
		http.Error(w, "Missing required fields: issuer, resource_id, scopes", http.StatusBadRequest)
		return
	}

	scopes := stringsToScopes(reqData.Scopes)

	logrus.WithFields(logrus.Fields{
		"issuer":      reqData.Issuer,
		"resource_id": reqData.ResourceID,
		"scopes":      reqData.Scopes,
	}).Info("Received resource registration request")

	if err := createResource(reqData.Issuer, reqData.ResourceID, scopes); err != nil {
		logrus.WithError(err).Error("Failed to create UMA resource")
		http.Error(w, "Failed to register resource", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func createResource(issuer string, resourceId string, scopes []Scope) error {
	// Fetch UMA configuration
	config, err := fetchUmaConfig(issuer)
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("Error while retrieving UMA configuration")
		return err
	}

	// Check if resource already registered
	UmaId := idIndex[resourceId]
	endpoint := config.ResourceRegistrationEndpoint
	method := "POST"
	if UmaId != "" {
		endpoint = endpoint + "/" + UmaId
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

	action := "Creating"
	if UmaId != "" {
		action = "Updating"
	}
	logrus.WithFields(logrus.Fields{"action": action, "resource_id": resourceId, "endpoint": endpoint}).Info("Processing UMA resource registration")

	res, err := signing.DoSignedRequest(req)
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

	if UmaId != "" {
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
		idIndex[resourceId] = responseData.ID
		issuerIndex[resourceId] = issuer
		logrus.WithFields(logrus.Fields{"resource_id": resourceId, "uma_id": responseData.ID}).Info("Registered resource with UMA")
	}
	return nil
}

// handleDeleteResource handles DELETE /resource requests
func handleDeleteResource(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var reqData struct {
		Issuer     string `json:"issuer"`
		ResourceID string `json:"resource_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqData); err != nil {
		logrus.WithError(err).Warn("Invalid JSON in request body")
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if reqData.Issuer == "" || reqData.ResourceID == "" {
		http.Error(w, "Missing required fields: issuer, resource_id", http.StatusBadRequest)
		return
	}

	logrus.WithFields(logrus.Fields{
		"issuer":      reqData.Issuer,
		"resource_id": reqData.ResourceID,
	}).Info("Received resource deletion request")

	if err := deleteResource(reqData.Issuer, reqData.ResourceID); err != nil {
		logrus.WithError(err).Debug("Failed to delete UMA resource")
		http.Error(w, fmt.Sprintf("Failed to delete resource: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// deleteResource deletes a single resource from the authorization server and updates local state
func deleteResource(issuer string, resourceId string) error {
	umaID, ok := idIndex[resourceId]
	if !ok {
		// Resource not registered / already deleted
		return fmt.Errorf("resource %s not found locally", resourceId)
	}

	config, err := fetchUmaConfig(issuer)
	if err != nil {
		return fmt.Errorf("failed to fetch UMA config: %w", err)
	}

	deleteURL := fmt.Sprintf("%s%s", config.ResourceRegistrationEndpoint, umaID)

	req, err := http.NewRequest("DELETE", deleteURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create DELETE request for resource %s: %w", resourceId, err)
	}

	// Set headers
	req.Header.Set("Accept", "application/json")

	res, err := signing.DoSignedRequest(req)
	if err != nil {
		return fmt.Errorf("failed to send signed DELETE request for resource %s: %w", resourceId, err)
	}
	defer res.Body.Close()

	// Successful deletion
	if res.StatusCode == http.StatusOK || res.StatusCode == http.StatusNoContent || res.StatusCode == http.StatusResetContent {
		// Remove local references
		delete(idIndex, resourceId)
		delete(issuerIndex, resourceId)
		logrus.WithFields(logrus.Fields{
			"resource": resourceId,
			"uma_id":   umaID,
		}).Info("Deleted UMA resource successfully")
		return nil
	}

	// Conflict due to non-empty collections
	if res.StatusCode == http.StatusConflict {
		body, _ := io.ReadAll(res.Body)
		logrus.WithFields(logrus.Fields{
			"resource": resourceId,
			"uma_id":   umaID,
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
	for resourceID, issuer := range issuerIndex {
		sem <- struct{}{} // acquire semaphore
		go func(res, iss string) {
			defer func() { <-sem }() // release semaphore
			err := deleteResource(iss, res)
			results <- deletionResult{resourceID: res, err: err}
		}(resourceID, issuer)
	}

	// Collect results
	var errs []error
	for i := 0; i < len(issuerIndex); i++ {
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

func SynchronizeResources(issuer string) error {
	logrus.Infof("Synchronizing resources with %s", issuer)

	// Fetch UMA configuration (to find the ResourceRegistrationEndpoint)
	config, err := fetchUmaConfig(issuer)
	if err != nil {
		return fmt.Errorf("failed to retrieve UMA configuration: %w", err)
	}

	// GET /resources — list of registered resource IDs
	listReq, err := http.NewRequest("GET", config.ResourceRegistrationEndpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create UMA resource list request: %w", err)
	}
	listReq.Header.Set("Accept", "application/json")

	logrus.WithFields(logrus.Fields{
		"issuer":   issuer,
		"endpoint": config.ResourceRegistrationEndpoint,
	}).Debug("Fetching UMA resource list")

	listRes, err := signing.DoSignedRequest(listReq)
	if err != nil {
		return fmt.Errorf("failed to send signed UMA resource list request: %w", err)
	}
	defer listRes.Body.Close()

	if listRes.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(listRes.Body)
		return fmt.Errorf("UMA resource list request failed with status %s: %s", listRes.Status, string(body))
	}

	// Parse list of UMA resource IDs
	var resourceIDs []string
	if err := json.NewDecoder(listRes.Body).Decode(&resourceIDs); err != nil {
		return fmt.Errorf("failed to parse UMA resource list: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"issuer":       issuer,
		"numResources": len(resourceIDs),
	}).Info("Received UMA resource list")

	// Loop through each UMA resource ID and fetch details
	for _, resourceID := range resourceIDs {
		detailURL := config.ResourceRegistrationEndpoint + "/" + resourceID

		detailReq, err := http.NewRequest("GET", detailURL, nil)
		if err != nil {
			logrus.WithError(err).WithField("resource_id", resourceID).Debug("Failed to create UMA resource detail request")
			continue
		}
		detailReq.Header.Set("Accept", "application/json")

		detailRes, err := signing.DoSignedRequest(detailReq)
		if err != nil {
			logrus.WithError(err).WithField("resource_id", resourceID).Debug("Failed to send UMA resource detail request")
			continue
		}
		defer detailRes.Body.Close()

		if detailRes.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(detailRes.Body)
			logrus.WithFields(logrus.Fields{
				"resource_id": resourceID,
				"status":      detailRes.Status,
				"body":        string(body),
			}).Debug("UMA resource detail request failed")
			continue
		}

		// Parse resource description + _id
		var resourceDetail struct {
			ID             string                 `json:"_id"`
			Name           string                 `json:"name"`
			ResourceScopes []string               `json:"resource_scopes"`
			OtherFields    map[string]interface{} `json:"-"` // ignore unknown fields
		}
		if err := json.NewDecoder(detailRes.Body).Decode(&resourceDetail); err != nil {
			logrus.WithError(err).WithField("resource_id", resourceID).Debug("Failed to parse UMA resource detail")
			continue
		}

		if resourceDetail.ID == "" || resourceDetail.Name == "" {
			logrus.WithField("resource_id", resourceID).Debug("UMA resource missing _id or name; skipping")
			continue
		}

		// Record UMA resource ID locally
		idIndex[resourceDetail.Name] = resourceDetail.ID
		issuerIndex[resourceDetail.Name] = issuer

		logrus.WithFields(logrus.Fields{
			"resource": resourceDetail.Name,
			"uma_id":   resourceDetail.ID,
			"scopes":   resourceDetail.ResourceScopes,
		}).Info("Synchronized UMA resource")
	}

	return nil
}
