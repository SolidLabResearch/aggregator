package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
)

var proxyPort = "5050"

func main() {
	http.HandleFunc("/", Handler)
	log.Println("Proxy listening on port: " + proxyPort)
	log.Fatal(http.ListenAndServe(":"+proxyPort, nil))
}

// TODO add a cache to the proxy

func Handler(w http.ResponseWriter, req *http.Request) {
	fmt.Println("Request received", req.Method, req.RequestURI)
	outReq, err := http.NewRequest(req.Method, req.RequestURI, req.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Copy headers ignore Authorization header
	for key, value := range req.Header {
		if key == "Authorization" {
			continue
		}
		for _, element := range value {
			outReq.Header.Add(key, element)
		}
	}

	resp, err := Do(outReq)
	if err != nil {
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response back
	for key, value := range resp.Header {
		w.Header()[key] = value
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
	location, _ := resp.Location()
	fmt.Println("Response ", location, resp.Status)
}
