package main

import (
	"log"
	"net/http"
)

const resourceSubscriptionPort = "4449"

func startResourceSubscriptionEndpoint() {
	serverMux := http.NewServeMux()
	serverMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {

		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})
	go func() {
		log.Println("Server listening on port: " + resourceSubscriptionPort)
		log.Fatal(http.ListenAndServe(":"+resourceSubscriptionPort, serverMux))
	}()
}

func resourceSubscriptionLocation() string {
	return "http://localhost" + resourceSubscriptionPort
}
