package main

import (
	"encoding/json"
	"net/http"
)

const AggregatorSpecVersion = "1.0.0"

type jsonLDID struct {
	ID   string `json:"@id"`
	Type string `json:"@type,omitempty"`
}

type serverDescriptionContext struct {
	Aggr                              string   `json:"aggr"`
	NoAuth                            string   `json:"none"`
	Provision                         string   `json:"provision"`
	AuthorizationCode                 string   `json:"authorization_code"`
	DeviceCode                        string   `json:"device_code"`
	SupportedManagementRequestFormats string   `json:"supported_management_request_formats"`
	ManagementEndpoint                jsonLDID `json:"management_endpoint"`
	SupportedManagementFlows          jsonLDID `json:"supported_management_flows"`
	Version                           jsonLDID `json:"version"`
	ClientIdentifier                  jsonLDID `json:"client_identifier"`
	TransformationCatalog             jsonLDID `json:"transformation_catalog"`
}

type serverDescription struct {
	Context                           serverDescriptionContext `json:"@context"`
	ID                                string                   `json:"@id"`
	Type                              string                   `json:"@type"`
	ManagementEndpoint                string                   `json:"management_endpoint"`
	SupportedManagementFlows          []string                 `json:"supported_management_flows"`
	SupportedManagementRequestFormats []string                 `json:"supported_management_request_formats"`
	Version                           string                   `json:"version"`
	ClientIdentifier                  string                   `json:"client_identifier"`
	TransformationCatalog             string                   `json:"transformation_catalog"`
}

type clientIDDocument struct {
	Context                 string   `json:"@context,omitempty"`
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name"`
	ApplicationType         string   `json:"application_type"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	JwksURI                 string   `json:"jwks_uri"`
	Scope                   string   `json:"scope,omitempty"`
}

func RegisterServerMetadataEndpoints(mux *http.ServeMux) {
	mux.HandleFunc("/", handleServerDescription)
	mux.HandleFunc("/client.jsonld", handleClientIDDocument)
	mux.HandleFunc("/transformations", handleTransformationCatalog)
}

func baseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func handleServerDescription(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	base := baseURL(r)
	description := serverDescription{
		Context: serverDescriptionContext{
			Aggr:                              "https://w3id.org/aggregator#",
			NoAuth:                            "aggr:NoAuthFlow",
			Provision:                         "aggr:ProvisionFlow",
			AuthorizationCode:                 "aggr:AuthorizationCodeFlow",
			DeviceCode:                        "aggr:DeviceCodeFlow",
			SupportedManagementRequestFormats: "aggr:registrationRequestFormatSupported",
			ManagementEndpoint: jsonLDID{
				ID:   "aggr:registrationEndpoint",
				Type: "@id",
			},
			SupportedManagementFlows: jsonLDID{
				ID:   "aggr:supportedRegistrationType",
				Type: "@vocab",
			},
			Version: jsonLDID{
				ID: "aggr:specVersion",
			},
			ClientIdentifier: jsonLDID{
				ID:   "aggr:clientIdentifier",
				Type: "@id",
			},
			TransformationCatalog: jsonLDID{
				ID:   "aggr:transformationCatalog",
				Type: "@id",
			},
		},
		ID:                                base + "/",
		Type:                              "aggr:AggregatorServer",
		ManagementEndpoint:                base + "/registration",
		SupportedManagementFlows:          []string{"none", "authorization_code"},
		SupportedManagementRequestFormats: []string{"application/json"},
		Version:                           AggregatorSpecVersion,
		ClientIdentifier:                  base + "/client.jsonld",
		TransformationCatalog:             base + "/transformations",
	}

	writeJSON(w, r, description, http.StatusOK)
}

func handleClientIDDocument(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	base := baseURL(r)
	document := clientIDDocument{
		Context:                 "https://www.w3.org/ns/solid/oidc-context.jsonld",
		ClientID:                base + "/client.jsonld",
		ClientName:              "Aggregator Server",
		ApplicationType:         "web",
		GrantTypes:              []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		JwksURI:                 base + "/.well-known/jwks.json",
		Scope:                   "openid webid offline_access",
	}

	writeJSON(w, r, document, http.StatusOK)
}

func handleTransformationCatalog(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/turtle")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write([]byte(hardcodedAvailableTransformations))
}

func writeJSON(w http.ResponseWriter, r *http.Request, value interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if r.Method == http.MethodHead {
		return
	}
	_ = json.NewEncoder(w).Encode(value)
}
