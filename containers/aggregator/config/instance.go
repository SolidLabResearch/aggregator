package config

import (
	"aggregator/auth"
	"aggregator/model"
	"fmt"
	"net/http"
	"strconv"

	"github.com/sirupsen/logrus"
)

type InstanceConfigData struct {
	etagTransformations int
	transformations     string
	owner               model.User
}

func InitInstanceConfiguration(mux *http.ServeMux, user model.User) error {
	logrus.Info("Initializing instance configuration")

	config := InstanceConfigData{
		etagTransformations: 0,
		transformations:     hardcodedInstanceTransformations,
		owner:               user,
	}

	// Register HTTP handler
	mux.HandleFunc("/transformations", config.HandleTransformationsEndpoint)

	// Build full URL
	fullURL := fmt.Sprintf("%s://%s/transformations", model.Protocol, model.ExternalHost)

	// Register resource
	if err := auth.RegisterResource(fullURL, model.AggregatorASURL, []model.Scope{model.Read}); err != nil {
		return fmt.Errorf("failed to register config resource %s: %w", fullURL, err)
	}

	// Define policy (owner only)
	if err := auth.DefinePolicy(fullURL, user.UserId, model.AggregatorASURL, []model.Scope{model.Read}); err != nil {
		return fmt.Errorf("failed to define policy for resource %s", fullURL)
	}

	logrus.Info("Instance configuration initialization completed")
	return nil
}

// HandleTransformationsEndpoint handles requests to the /transformations endpoint
func (config InstanceConfigData) HandleTransformationsEndpoint(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "HEAD":
		config.headAvailableTransformations(w, r)
	case "GET":
		config.getAvailableTransformations(w, r)
	default:
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

// getAvailableTransformations HEAD /transformations retrieves all available transformations
func (config *InstanceConfigData) headAvailableTransformations(w http.ResponseWriter, _ *http.Request) {
	header := w.Header()
	header.Set("ETag", strconv.Itoa(config.etagTransformations))
	header.Set("Content-Type", "text/turtle")
}

// getAvailableTransformations GET /transformations retrieves all available transformations
func (config *InstanceConfigData) getAvailableTransformations(w http.ResponseWriter, _ *http.Request) {
	header := w.Header()
	header.Set("ETag", strconv.Itoa(config.etagTransformations))
	header.Set("Content-Type", "text/turtle")
	_, err := w.Write([]byte(config.transformations))
	if err != nil {
		http.Error(w, "error when writing body", http.StatusInternalServerError)
	}
}

const hardcodedInstanceTransformations = `
@base <http://localhost:5000/transformations#> .
@prefix fno: <https://w3id.org/function/ontology#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .

# Placeholder for user-specific transformations
`
