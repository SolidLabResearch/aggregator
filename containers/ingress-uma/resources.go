package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"ingress-uma/signing"

	"github.com/sirupsen/logrus"
)

type Scope string

const (
	Read   Scope = "urn:example:css:modes:read"
	Append Scope = "urn:example:css:modes:append"
	Create Scope = "urn:example:css:modes:create"
	Delete Scope = "urn:example:css:modes:delete"
	Write  Scope = "urn:example:css:modes:write"
)

var idIndex = make(map[string]string)

func CreateResource(issuer string, resourceId string, scopes []Scope) error {
	config, err := fetchUmaConfig(issuer)
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("Error while retrieving UMA configuration")
		return err
	}

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
		logrus.WithFields(logrus.Fields{"resource_id": resourceId, "uma_id": responseData.ID}).Info("Registered resource with UMA")
	}
	return nil
}
