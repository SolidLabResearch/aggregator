package config

import (
	"aggregator/auth"
	"aggregator/model"
	"fmt"
	"net/http"
	"strconv"

	"github.com/sirupsen/logrus"
)

type AdminConfigData struct {
	etagTransformations int
	transformations     string
}

func InitAdminConfiguration(mux *http.ServeMux) error {
	logrus.Info("Initializing admin configuration")

	config := AdminConfigData{
		etagTransformations: 0,
		transformations:     hardcodedAvailableTransformations,
	}

	// Register HTTP handler
	mux.HandleFunc("/config/transformations", config.HandleTransformationsEndpoint)

	// Build full URL
	fullURL := fmt.Sprintf("%s://%s/config", model.Protocol, model.ExternalHost)

	// Register resource
	if err := auth.RegisterResource(fullURL, model.AggregatorASURL, []model.Scope{model.Read, model.Write}); err != nil {
		return fmt.Errorf("failed to register config resource %s: %w", fullURL, err)
	}

	// Define public policy
	if err := auth.DefinePublicPolicy(fullURL, model.AggregatorASURL, []model.Scope{model.Read}); err != nil {
		return fmt.Errorf("failed to define public read policy for resource %s: %w", fullURL, err)
	}

	// Define admin policy
	if err := auth.DefinePolicy(fullURL, model.AdminId, model.AggregatorASURL, []model.Scope{model.Write}); err != nil {
		return fmt.Errorf("failed to define admin write policy for resource %s", fullURL)
	}

	logrus.Info("Admin configuration initialization completed")
	return nil
}

// HandleTransformationsEndpoint handles requests to the /config/transformations endpoint
func (config AdminConfigData) HandleTransformationsEndpoint(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "HEAD":
		config.headAvailableTransformations(w, r)
	case "GET":
		config.getAvailableTransformations(w, r)
	default:
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

// getAvailableTransformations HEAD /config/transformations retrieves all available transformations
func (config *AdminConfigData) headAvailableTransformations(w http.ResponseWriter, _ *http.Request) {
	header := w.Header()
	header.Set("ETag", strconv.Itoa(config.etagTransformations))
	header.Set("Content-Type", "text/turtle")
}

// getAvailableTransformations GET /config/transformations retrieves all available transformations
func (config *AdminConfigData) getAvailableTransformations(w http.ResponseWriter, _ *http.Request) {
	header := w.Header()
	header.Set("ETag", strconv.Itoa(config.etagTransformations))
	header.Set("Content-Type", "text/turtle")
	_, err := w.Write([]byte(config.transformations))
	if err != nil {
		http.Error(w, "error when writing body", http.StatusInternalServerError)
	}
}

const hardcodedAvailableTransformations = `
@base <http://localhost:5000/config/transformations#> .
@prefix fno: <https://w3id.org/function/ontology#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .

# SPARQL execution
<SPARQLEvaluation>
	a                   fno:Function ;
	fno:name            "A SPARQL query engine"^^xsd:string ;
	fno:expects         ( <QueryString> <Sources> ) ;

<QueryString>
	a             fno:Parameter ;
	fno:predicate <queryString> ;
	fno:type      xsd:string ;
	fno:required  "true"^^xsd:boolean .

<Sources>
	a             fno:Parameter ;
	fno:predicate <sources> ;
	fno:type      rdf:List .
	fno:required  "true"^^xsd:boolean .

<SPARQLQueryResultSource>
    a owl:Class ;
    rdfs:label "SPARQL Query Result Source"@en .

<sparqlQueryResult>
	a rdf:Property ;
    rdfs:domain <SPARQLQueryResultSource> ;
    rdfs:range xsd:anyURI .

<extractVariables>
	a rdf:Property ;
    rdfs:domain <SPARQLQueryResultSource> ;
    rdfs:range rdf:List 
`
