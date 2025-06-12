package main

import (
	"aggregator/auth"
	"encoding/json"
	"fmt"
	"net/http"
)

type Transformation struct {
	Sources        []string `json:"sources"`
	Transformation string   `json:"transformation"`
}

type ConfigurationData struct {
	etag                         int
	actors                       map[string]Actor
	actorsJson                   string
	availableTransformationsJson string
}

func startConfigurationEndpoint(location string, mux *http.ServeMux) {
	configurationData := ConfigurationData{
		etag:                         0,
		actors:                       make(map[string]Actor),
		actorsJson:                   "\"actors\":[]",
		availableTransformationsJson: "\"availableTransformations\":[]",
	}
	mux.HandleFunc("/"+location, configurationData.ConfigurationEndpoint)
	const resourceDescription = "{\"resource_scopes\": [\"urn:example:css:modes:read\",\"urn:example:css:modes:append\",\"urn:example:css:modes:create\",\"urn:example:css:modes:delete\",\"urn:example:css:modes:write\"]}"
	auth.CreateResource(
		fmt.Sprintf("%s://%s:%s/%s", protocol, host, serverPort, location),
		resourceDescription,
	)
}

func (data ConfigurationData) ConfigurationEndpoint(response http.ResponseWriter, request *http.Request) {
	// 1) Authorize request
	if !auth.AuthorizeRequest(response, request, nil) {
		return
	}

	switch request.Method {
	case "HEAD":
		data.head(response, request)
	case "GET":
		data.get(response, request)
	case "POST":
		data.post(response, request)
	case "DELETE":
		data.delete(response, request)
	default:
		http.Error(response, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

func (data ConfigurationData) head(response http.ResponseWriter, _ *http.Request) {
	// mainly set etag => change etag when transformation is added/removed
	header := response.Header()
	header.Set("ETag", string(rune(data.etag)))
	response.WriteHeader(http.StatusOK)
}

func (data ConfigurationData) get(response http.ResponseWriter, _ *http.Request) {
	// return all actors (with id's)
	header := response.Header()
	header.Set("ETag", string(rune(data.etag)))
	header.Set("Content-Type", "application/json")
	_, err := response.Write([]byte("{" + data.actorsJson + ", " + data.availableTransformationsJson + "}"))
	if err != nil {
		println(err.Error())
		http.Error(response, "error when writing body", http.StatusInternalServerError)
	}
}

func (data ConfigurationData) post(response http.ResponseWriter, request *http.Request) {
	// 2) get transformation and sources from request body
	var transformation Transformation
	err := json.NewDecoder(request.Body).Decode(&transformation)
	if err != nil {
		println(err.Error())
		http.Error(response, "Invalid request payload", http.StatusBadRequest)
		return
	}
	defer request.Body.Close()
	fmt.Printf("Transformation: %v\n", transformation)

	actor, err := createActor(transformation)

	if err != nil {
		fmt.Println("Failed to create an actor: " + err.Error())
		http.Error(response, "Failed to create the transformation", http.StatusInternalServerError)
		return
	}

	data.actors[actor.Id] = actor
	data.updateData()

	// 5) return the endpoint to the client
	header := response.Header()
	header.Set("Content-Type", "application/json")
	_, err = response.Write([]byte(actor.marshalActor()))
}

func (data ConfigurationData) delete(response http.ResponseWriter, request *http.Request) {
	// 2) get id from request
	id := request.URL.Query().Get("id")
	fmt.Printf("Delete transformation: %v\n", id)

	// 3) delete transformation with id
	_, ok := data.actors[id]
	if !ok {
		http.Error(response, "transformation with id "+id+" not found", http.StatusNotFound)
		return
	}
	//data.actors[id].Pod.
	delete(data.actors, id)

	// 4) stop actor
	data.updateData()
	response.WriteHeader(http.StatusOK)
}

func (data ConfigurationData) updateData() {
	data.actorsJson = "\"actors\":["
	for _, actor := range data.actors {
		actorJson := actor.marshalActor()
		data.actorsJson += "\"" + actorJson + "\","
	}
	data.actorsJson += "]"
	data.etag += 1
}
