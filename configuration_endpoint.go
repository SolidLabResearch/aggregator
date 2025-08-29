package main

import (
	"aggregator/auth"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

type ConfigurationData struct {
	etagActors               int
	etagTransformations      int
	actors                   map[string]Actor
	availableTransformations string
	serveMux                 *http.ServeMux
}

// /config/ => read => a get to retrieve all transformations & head to get etag of transformations
// /config/actors/ => read, create => has get to retrieve all actors and their IDs, head to get etag, post to create a new actor
// /config/actors/{id} => read, delete => has get to retrieve an actor with the given ID, head to get etag, delete to delete an actor with the given ID
func startConfigurationEndpoint(mux *http.ServeMux) {
	configurationData := ConfigurationData{
		etagActors:               0,
		etagTransformations:      0,
		actors:                   make(map[string]Actor),
		availableTransformations: hardcodedAvailableTransformations,
		serveMux:                 mux,
	}

	configurationData.HandleFunc("/config", configurationData.HandleConfigurationEndpoint, resourceScopesRead)
	configurationData.HandleFunc("/config/actors", configurationData.HandleActorsEndpoint, resourceScopesReadCreate)
}

func (data ConfigurationData) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request), resourceScopes []auth.ResourceScope) {
	data.serveMux.HandleFunc(pattern, handler)
	auth.CreateResource(
		fmt.Sprintf("%s://%s:%s%s", Protocol, Host, ServerPort, pattern),
		resourceScopes,
	)
}

// HandleConfigurationEndpoint handles requests to the /config endpoint
func (data ConfigurationData) HandleConfigurationEndpoint(response http.ResponseWriter, request *http.Request) {
	// 1) Authorize request
	if !auth.AuthorizeRequest(response, request, nil) {
		return
	}

	switch request.Method {
	case "HEAD":
		data.headAvailableTransformations(response, request)
	case "GET":
		data.getAvailableTransformations(response, request)
	default:
		http.Error(response, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

// getAvailableTransformations GET config/transformations retrieves all available transformations
func (data ConfigurationData) headAvailableTransformations(response http.ResponseWriter, _ *http.Request) {
	header := response.Header()
	header.Set("ETag", strconv.Itoa(data.etagTransformations))
	header.Set("Content-Type", "text/turtle")
}

// getAvailableTransformations GET config/transformations retrieves all available transformations
func (data ConfigurationData) getAvailableTransformations(response http.ResponseWriter, _ *http.Request) {
	header := response.Header()
	header.Set("ETag", strconv.Itoa(data.etagTransformations))
	header.Set("Content-Type", "text/turtle")
	_, err := response.Write([]byte(data.availableTransformations))
	if err != nil {
		println(err.Error())
		http.Error(response, "error when writing body", http.StatusInternalServerError)
	}
}

// HandleActorsEndpoint handles requests to the /config/actors endpoint
func (data ConfigurationData) HandleActorsEndpoint(response http.ResponseWriter, request *http.Request) {
	// 1) Authorize request
	if !auth.AuthorizeRequest(response, request, nil) {
		return
	}

	if request.URL.Path == "/config/actors" {
		switch request.Method {
		case "HEAD":
			data.headActors(response, request)
		case "GET":
			data.getActors(response, request)
		case "POST":
			data.createActor(response, request)
		default:
			http.Error(response, "Invalid request method", http.StatusMethodNotAllowed)
		}
		return
	}
}

// headActors config mainly returns the ETag header
func (data ConfigurationData) headActors(response http.ResponseWriter, _ *http.Request) {
	header := response.Header()
	header.Set("Content-Type", "application/json")
	header.Set("ETag", strconv.Itoa(data.etagActors))
	response.WriteHeader(http.StatusOK)
}

// getActors GET config retrieves all actors and their IDs
func (data ConfigurationData) getActors(response http.ResponseWriter, _ *http.Request) {
	header := response.Header()
	header.Set("Content-Type", "application/json")
	fmt.Printf("Request get for actors, etag: %v\n", data.etagActors)
	header.Set("ETag", strconv.Itoa(data.etagActors))
	// TODO not sure yet how this should be returned
	actors := "{\"actors\":["
	ids := []string{}
	for _, actor := range data.actors {
		ids = append(ids, "\""+actor.Id+"\"")
	}
	actors += strings.Join(ids, ",")
	actors += "]}"
	_, err := response.Write([]byte(actors))
	if err != nil {
		println(err.Error())
		http.Error(response, "error when writing body", http.StatusInternalServerError)
	}
}

// createActor creates a new actor
// Should we need to set limitations on these transformations? => like what if we only allow 1 source or don't allow a certain SPARQL query? => 405
// What if we only allow one single pipeline that can be instantiated? => I guess return 405?
// What if the transformation takes to long to execute => return 202 but then when the user tries to get the results, we return 404 with extra information that the transformation is still running/canceled?
func (data ConfigurationData) createActor(response http.ResponseWriter, request *http.Request) {
	// 2) get transformation and sources from request body
	pipelineDescription, err := io.ReadAll(request.Body)
	if err != nil {
		println(err.Error())
		http.Error(response, "Invalid request payload", http.StatusBadRequest)
		return
	}
	defer request.Body.Close()
	fmt.Printf("Transformation: %v\n", string(pipelineDescription))

	actor, err := createActor(string(pipelineDescription))

	if err != nil {
		fmt.Println("Failed to create an actor: " + err.Error())
		http.Error(response, "Failed to create the actor", http.StatusInternalServerError)
		return
	}

	data.actors[actor.Id] = actor
	data.etagActors++ // TODO maybe hash the actors to get a unique etag

	// TODO the descriptions need to have the pipelineDescription
	data.HandleFunc(fmt.Sprintf("/config/actors/%s", actor.Id), data.HandleActorEndpoint, resourceScopesReadDelete)

	// 5) return the endpoint to the client
	header := response.Header()
	header.Set("Content-Type", "test/plain")
	_, err = response.Write([]byte(actor.marshalActor()))
}

// HandleActorEndpoint handles requests to the /config/actors/{id} endpoint
func (data ConfigurationData) HandleActorEndpoint(response http.ResponseWriter, request *http.Request) {
	// 2) get id from request
	parts := strings.Split(request.URL.Path, "/")
	if len(parts) < 4 || parts[3] == "" {
		http.Error(response, "Invalid request path", http.StatusBadRequest)
		return
	}
	actor, ok := data.actors[parts[3]]
	if !ok {
		http.Error(response, "Actor with id "+parts[3]+" not found", http.StatusNotFound)
		return
	}

	switch request.Method {
	case "HEAD":
		data.headActor(response, request, actor)
	case "GET":
		data.getActor(response, request, actor)
	case "DELETE":
		data.deleteActor(response, request, actor)
	default:
		http.Error(response, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

// headActor HEAD config/actors/{id} returns the ETag header for the actor with the given ID
func (data ConfigurationData) headActor(response http.ResponseWriter, request *http.Request, actor Actor) {
	fmt.Printf("Request head for actor: %v\n", actor.Id)

	header := response.Header()
	header.Set("Content-Type", "application/json")
	header.Set("ETag", "0") // TODO: actors can't be changed, so they will always return the same value so ETag is always 0 (for now)
	response.WriteHeader(http.StatusOK)
}

func (data ConfigurationData) getActor(response http.ResponseWriter, request *http.Request, actor Actor) {
	fmt.Printf("Request get for actor: %v\n", actor.Id)

	header := response.Header()
	header.Set("Content-Type", "application/json")
	header.Set("ETag", "0") // TODO: actors can't be changed, so they will always return the same value so ETag is always 0 (for now)
	_, err := response.Write([]byte(actor.marshalActor()))
	if err != nil {
		println(err.Error())
		http.Error(response, "error when writing body", http.StatusInternalServerError)
	}
}

// DELETE config deletes an actor with the given ID
func (data ConfigurationData) deleteActor(response http.ResponseWriter, _ *http.Request, actor Actor) {
	fmt.Printf("Request to delete transformation: %v\n", actor.Id)

	actor.Stop()
	delete(data.actors, actor.Id)

	data.etagActors++
	response.WriteHeader(http.StatusOK)

	auth.DeleteResource(
		fmt.Sprintf("%s://%s:%s/config/actors/%s", Protocol, Host, ServerPort, actor.Id),
	)
}

// Replace resourceScopes* slices with enum slices using auth.ResourceScope
var resourceScopesRead = []auth.ResourceScope{auth.ScopeRead}
var resourceScopesReadDelete = []auth.ResourceScope{auth.ScopeRead, auth.ScopeDelete}
var resourceScopesReadCreate = []auth.ResourceScope{auth.ScopeRead, auth.ScopeCreate}

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
@prefix config: <http://localhost:5000/config#> .
@prefix fno: <https://w3id.org/function/ontology#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .

# SPARQL execution
config:SPARQLEvaluation
	a                   fno:Function ;
	fno:name            "A SPARQL query engine"^^xsd:string ;
	fno:expects         ( config:QueryString config:Sources ) ;

config:QueryString
	a             fno:Parameter ;
	fno:predicate config:queryString ;
	fno:type      xsd:string ;
	fno:required  "true"^^xsd:boolean .

config:Sources
	a             fno:Parameter ;
	fno:predicate config:sources ;
	fno:type      rdf:List .
	fno:required  "true"^^xsd:boolean .
`
