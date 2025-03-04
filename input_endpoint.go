package main

import (
	"net/http"
)

func inputEndpoint(response http.ResponseWriter, request *http.Request) {
	// Do UMA flow here:
	// 		If unauthenticated get token from Authorization server and send it as response
	// 		If authenticated check token with Authorization server
	//let check_access(response, request);

	// Start query probably in a docker container and somehow connect the endpoint and the docker container
	// Send the endpoint to the user
}
