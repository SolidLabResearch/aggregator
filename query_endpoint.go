package main

import "net/http"

func queryEndpoint(response http.ResponseWriter, request *http.Request) {
	// Do UMA flow here:
	// 		If unauthenticated get token from Authorization server and send it as response
	// 		If authenticated check token with Authorization server
	// Get the result from the query and send it as response
}
