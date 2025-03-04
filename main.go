package main

import (
	"fmt"
)

var protocol = "http"
var host = "localhost"
var port = "5000"
var accessToken = ""

func main() {
	initSigning()
	go func() {
		//http.HandleFunc("/input", inputEndpoint)
		//http.HandleFunc("/query", queryEndpoint)
		//http.HandleFunc("/.well-known/jwks.json", jwksHandler)
		//println("listening on port " + port)
		//err := http.ListenAndServe(":"+port, nil)
		//if err != nil {
		//fmt.Println("Error starting server:", err)
		//}
	}()

	//config, err := fetchUmaConfig("http://localhost:4000/uma")
	permissions := map[string][]string{
		"http://localhost:5000/test": {"modify"},
	}
	println("fetchTicket")
	ticket, err := fetchTicket(permissions, "http://localhost:4000/uma")
	if err != nil {
		println(fmt.Errorf("error while retrieving ticket: %v", err).Error())
	}
	println(ticket)
	var token string
	fmt.Print("Enter token: ")
	fmt.Scanln(&token)
	fmt.Println("You entered:", token)

	err = verifyTicket(token, []string{"http://localhost:4000/uma"})
	if err != nil {
		fmt.Printf("error while verifying ticket: %v\n", err)
	} else {
		fmt.Printf("ticket verified and valid.\n")
	}

	//createResource("http://localhost:5000/query/sdvdcvweqeg", "http://localhost:4000/uma")
}
