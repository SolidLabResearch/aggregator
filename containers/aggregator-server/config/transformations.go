package config

import (
	"aggregator/model"
	"fmt"
	"net/http"
	"strconv"

	"github.com/sirupsen/logrus"
)

type TransformationsConfigData struct {
	etagTransformations int
	transformations     string
}

func InitTransformationsConfiguration(mux *http.ServeMux) error {
	logrus.Info("Initializing transformations configuration")

	transformations := fmt.Sprintf(hardcodedAvailableTransformationsTemplate, model.ExternalHost)

	config := TransformationsConfigData{
		etagTransformations: 0,
		transformations:     transformations,
	}

	// Register HTTP handler
	mux.HandleFunc("/config/transformations", config.HandleTransformationsEndpoint)

	logrus.Info("Transformations configuration initialization completed")
	return nil
}

// HandleTransformationsEndpoint handles requests to the /config/transformations endpoint
func (config TransformationsConfigData) HandleTransformationsEndpoint(w http.ResponseWriter, r *http.Request) {
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
func (config *TransformationsConfigData) headAvailableTransformations(w http.ResponseWriter, r *http.Request) {
	accept := r.Header.Get("Accept")
	if accept != "" && accept != "*/*" && accept != "text/turtle" {
		http.Error(w, "Unsupported Media Type. Only text/turtle is supported.", http.StatusUnsupportedMediaType)
		return
	}

	header := w.Header()
	header.Set("ETag", strconv.Itoa(config.etagTransformations))
	header.Set("Content-Type", "text/turtle")
}

// getAvailableTransformations GET /config/transformations retrieves all available transformations
func (config *TransformationsConfigData) getAvailableTransformations(w http.ResponseWriter, r *http.Request) {
	accept := r.Header.Get("Accept")
	if accept != "" && accept != "*/*" && accept != "text/turtle" {
		http.Error(w, "Unsupported Media Type. Only text/turtle is supported.", http.StatusUnsupportedMediaType)
		return
	}

	header := w.Header()
	header.Set("ETag", strconv.Itoa(config.etagTransformations))
	header.Set("Content-Type", "text/turtle")
	_, err := w.Write([]byte(config.transformations))
	if err != nil {
		http.Error(w, "error when writing body", http.StatusInternalServerError)
	}
}

const hardcodedAvailableTransformationsTemplate = `
@base <http://%s/config/transformations#> .
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
