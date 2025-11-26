package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type AdminConfigData struct {
	etagTransformations int
	transformations     string
}

func initAdminConfiguration(mux *http.ServeMux) {
	config := AdminConfigData{
		etagTransformations: 0,
		transformations:     hardcodedAvailableTransformations,
	}
	mux.HandleFunc("/config", config.HandleConfigurationEndpoint)
	registerResource(
		fmt.Sprintf("%s://%s/config", Protocol, ExternalHost),
		AggregatorASURL,
		[]Scope{Read, Write},
	)
	definePublicPolicy(
		fmt.Sprintf("%s://%s/config", Protocol, ExternalHost),
		AggregatorASURL,
		[]Scope{Read},
	)
	definePolicy(
		fmt.Sprintf("%s://%s/config", Protocol, ExternalHost),
		AdminId,
		AggregatorASURL,
		[]Scope{Write},
	)
}

// HandleConfigurationEndpoint handles requests to the /config endpoint
func (config AdminConfigData) HandleConfigurationEndpoint(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "HEAD":
		config.headAvailableTransformations(w, r)
	case "GET":
		config.getAvailableTransformations(w, r)
	default:
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

// getAvailableTransformations HEAD config/ retrieves all available transformations
func (config *AdminConfigData) headAvailableTransformations(w http.ResponseWriter, _ *http.Request) {
	header := w.Header()
	header.Set("ETag", strconv.Itoa(config.etagTransformations))
	header.Set("Content-Type", "text/turtle")
}

// getAvailableTransformations GET config/ retrieves all available transformations
func (config *AdminConfigData) getAvailableTransformations(w http.ResponseWriter, _ *http.Request) {
	header := w.Header()
	header.Set("ETag", strconv.Itoa(config.etagTransformations))
	header.Set("Content-Type", "text/turtle")
	_, err := w.Write([]byte(config.transformations))
	if err != nil {
		http.Error(w, "error when writing body", http.StatusInternalServerError)
	}
}

type UserConfigData struct {
	owner               User
	etagActors          int
	etagTransformations int
	actors              map[string]Actor
	eventHub            *EventHub
	serveMux            *http.ServeMux
}

func initUserConfiguration(mux *http.ServeMux, user User) {
	config := UserConfigData{
		owner:               user,
		etagActors:          0,
		etagTransformations: 0,
		actors:              make(map[string]Actor),
		eventHub:            NewEventHub(),
		serveMux:            mux,
	}

	config.HandleFunc(fmt.Sprintf("/config/%s/actors", user.Namespace), config.HandleActorsEndpoint, []Scope{Read, Create})
}

func (config *UserConfigData) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request), scopes []Scope) {
	config.serveMux.HandleFunc(pattern, handler)
	registerResource(
		fmt.Sprintf("%s://%s%s", Protocol, ExternalHost, pattern),
		AggregatorASURL,
		scopes,
	)
	definePolicy(
		fmt.Sprintf("%s://%s%s", Protocol, ExternalHost, pattern),
		config.owner.UserId,
		AggregatorASURL,
		scopes,
	)
}

// HandleActorsEndpoint handles requests to the /config/<namespace>/actors endpoint
func (config *UserConfigData) HandleActorsEndpoint(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "HEAD":
		config.headActors(w, r)
	case "GET":
		config.getActors(w, r)
	case "POST":
		config.postActor(w, r)
	default:
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
}

func (config *UserConfigData) headActors(w http.ResponseWriter, _ *http.Request) {
	header := w.Header()
	header.Set("Content-Type", "application/json")
	header.Set("ETag", strconv.Itoa(config.etagActors))
	w.WriteHeader(http.StatusOK)
}

func (config *UserConfigData) getActors(w http.ResponseWriter, _ *http.Request) {
	actorList := []Actor{}
	for _, actor := range config.actors {
		actorList = append(actorList, actor)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", strconv.Itoa(config.etagActors))
	err := json.NewEncoder(w).Encode(actorList)
	if err != nil {
		logrus.WithError(err).Error("Failed to encode actor list")
		http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
		return
	}
}

type ActorRequest struct {
	Id          string `json:"id"`
	Description string `json:"description"`
	Owner       User   `json:"owner"`
}

func (config *UserConfigData) postActor(w http.ResponseWriter, r *http.Request) {
	logrus.Info("Recieved request to register a actor")
	// read request body
	var request ActorRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// add request metadata
	request.Owner = config.owner
	if request.Id == "" {
		request.Id = uuid.NewString()
	}

	if _, exists := config.actors[request.Id]; exists {
		http.Error(w, "Actor id already registered for user", http.StatusConflict)
		return
	}

	// create actor
	actor, err := createActor(request)
	if err != nil {
		logrus.WithError(err).Error("Failed to create actor")
		http.Error(w, fmt.Sprintf("Failed to create actor: %v", err), http.StatusInternalServerError)
		return
	}

	// Store actor
	config.actors[request.Id] = *actor
	config.etagActors++

	// Create config and status endpoints
	config.HandleFunc(fmt.Sprintf("/config/%s/actors/%s", actor.namespace, actor.id), config.HandleActorEndpoint, []Scope{Read})
	config.HandleFunc(fmt.Sprintf("/config/%s/actors/%s/status", actor.namespace, actor.id), config.HandleStatusEndpoint, []Scope{Read})

	// Start watching deployments for readiness
	config.eventHub.WatchActorDeployments(actor)

	// Return actor information to the client
	w.Header().Set("Content-Type", "application/json")

	responseBytes, err := json.Marshal(actor)
	if err != nil {
		logrus.WithError(err).Error("Failed to marshal actor response")
		http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusAccepted)
	_, err = w.Write(responseBytes)
	if err != nil {
		logrus.WithError(err).Error("Error writing create actor response")
		return
	}
}

// SSE endpoint: /config/actors/<namespace>/<id>/status
func (config *UserConfigData) HandleStatusEndpoint(w http.ResponseWriter, r *http.Request) {
	// Parse actor ID from the URL
	parts := strings.Split(r.URL.Path, "/")
	id := parts[4]

	actor, ok := config.actors[id]
	if !ok {
		http.Error(w, "Actor not found", http.StatusNotFound)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// Subscribe to event updates
	eventCh := config.eventHub.Subscribe(actor.id)
	defer config.eventHub.Unsubscribe(actor.id, eventCh)

	// Initial message: connected
	fmt.Fprintf(w, "data: %s\n\n", `{"type":"info","message":"Connected to actor status stream"}`)
	flusher.Flush()

	// Main loop: stream events
	for {
		select {
		case event := <-eventCh:
			payload, _ := json.Marshal(event)
			fmt.Fprintf(w, "data: %s\n\n", payload)
			flusher.Flush()

			if event.Type == "complete" || event.Type == "error" {
				return
			}

		case <-r.Context().Done():
			// Client disconnected
			return
		}
	}
}

// HandleActorEndpoint handles requests to the /config/<namespace>/actors/<id> endpoint
func (config *UserConfigData) HandleActorEndpoint(w http.ResponseWriter, r *http.Request) {
	// Parse actor ID from the URL
	parts := strings.Split(r.URL.Path, "/")
	id := parts[4]

	actor, ok := config.actors[id]
	if !ok {
		http.Error(w, "Actor not found", http.StatusNotFound)
		return
	}

	switch r.Method {
	case "HEAD":
		config.headActor(w, r, actor)
	case "GET":
		config.getActor(w, r, actor)
	case "DELETE":
		config.deleteActor(w, r, actor)
	default:
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

// generateActorETag generates a consistent ETag based on the marshaled actor data
func generateActorETag(marshaledData []byte) string {
	hash := sha256.Sum256(marshaledData)
	return hex.EncodeToString(hash[:8]) // Use first 8 bytes for a shorter ETag
}

// headActor HEAD config/actors/<namespace>/<id> returns the ETag header for the actor with the given ID
func (config *UserConfigData) headActor(w http.ResponseWriter, _ *http.Request, actor Actor) {
	logrus.WithFields(logrus.Fields{"actor_id": actor.id}).Debug("Request HEAD for actor")

	marshaledData, err := json.Marshal(&actor)
	if err != nil {
		logrus.WithError(err).Error("Failed to marshal actor for HEAD request")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	header := w.Header()
	header.Set("Content-Type", "application/json")
	header.Set("ETag", generateActorETag(marshaledData))
	w.WriteHeader(http.StatusOK)
}

// getActor GET config/actors/<namespace>/<id> returns the full actor JSON with ETag
func (config *UserConfigData) getActor(w http.ResponseWriter, _ *http.Request, actor Actor) {
	logrus.WithFields(logrus.Fields{"actor_id": actor.id}).Info("Request GET for actor")

	marshaledData, err := json.Marshal(&actor)
	if err != nil {
		logrus.WithError(err).Error("Failed to marshal actor for GET request")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	header := w.Header()
	header.Set("Content-Type", "application/json")
	header.Set("ETag", generateActorETag(marshaledData))

	_, err = w.Write(marshaledData)
	if err != nil {
		logrus.WithError(err).Error("Error writing actor response body")
	}
}

// DELETE config deletes an actor with the given ID
func (config *UserConfigData) deleteActor(w http.ResponseWriter, _ *http.Request, actor Actor) {
	logrus.WithFields(logrus.Fields{"actor_id": actor.id}).Info("Request to delete transformation")

	actor.Stop()
	delete(config.actors, actor.id)

	config.etagActors++
	w.WriteHeader(http.StatusOK)
}

/*
const hardcodedAvailableTransformations = `
@prefix config: <http://localhost:5000/config#> .
@prefix fno: <https://w3id.org/function/ontology#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .

config:FileRelay
	a                   fno:Function ;
	fno:name            "Download files, concatenate them, and host the result" ;
	fno:expects         ( config:Sources ) .

config:Sources
	a             fno:Parameter ;
	fno:predicate config:sources ;
	fno:type      rdf:List .
	fno:required  "true"^^xsd:boolean .
`
*/

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
