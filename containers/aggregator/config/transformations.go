package config

import (
	"aggregator/auth"
	"aggregator/model"
	"fmt"
	"net/http"
	"strconv"

	"github.com/sirupsen/logrus"
)

type TransformationCatalog struct {
	etagTransformations int
	transformations     string
}

func InitTransformationCatalog(mux *http.ServeMux) error {
	logrus.Debugf("Initializing transformation catalog at %s", model.TransformationCatalog)

	catalog := TransformationCatalog{
		etagTransformations: 0,
		transformations:     hardcodedInstanceTransformations,
	}

	// Register HTTP handler
	mux.HandleFunc(model.TransformationCatalog, catalog.HandleTransformationsEndpoint)
	logrus.Infof("Handler registered at %s", model.TransformationCatalog)

	// Register catalog resource and policy
	fullURL := model.BaseUrl + model.TransformationCatalog
	if err := auth.RegisterResource(fullURL, []model.Scope{model.Read}); err != nil {
		return fmt.Errorf("failed to register resource %s: %w", fullURL, err)
	}
	if err := auth.DefinePolicy(fullURL, []model.Scope{model.Read}); err != nil {
		return fmt.Errorf("failed to define policy for resource %s: %w", fullURL, err)
	}

	logrus.Infof("Initialized transformation catalog at %s", model.TransformationCatalog)
	return nil
}

// HandleTransformationsEndpoint handles requests to the /transformations endpoint
func (catalog TransformationCatalog) HandleTransformationsEndpoint(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "HEAD":
		catalog.headAvailableTransformations(w, r)
	case "GET":
		catalog.getAvailableTransformations(w, r)
	default:
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

// getAvailableTransformations HEAD /transformations retrieves all available transformations
func (catalog *TransformationCatalog) headAvailableTransformations(w http.ResponseWriter, _ *http.Request) {
	header := w.Header()
	header.Set("ETag", strconv.Itoa(catalog.etagTransformations))
	header.Set("Content-Type", "text/turtle")
}

// getAvailableTransformations GET /transformations retrieves all available transformations
func (catalog *TransformationCatalog) getAvailableTransformations(w http.ResponseWriter, _ *http.Request) {
	header := w.Header()
	header.Set("ETag", strconv.Itoa(catalog.etagTransformations))
	header.Set("Content-Type", "text/turtle")
	_, err := w.Write([]byte(catalog.transformations))
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
