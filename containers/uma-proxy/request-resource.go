package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

var aggregatorOwner = "https://pod.playground.solidlab.be/user1/profile/card#me"

type claim struct {
	grantType        string `json:"grant_type"`
	ticket           string `json:"ticket"`
	claimToken       string `json:"claim_token"`
	claimTokenFormat string `json:"claim_token_format"`
}

var client = &http.Client{}

func Do(req *http.Request) (*http.Response, error) {
	// Do UMA flow here:
	// 		request resource
	// 		If unauthenticated go to Authorization server and with token
	// 			If unauthenticated return unauthenticated response
	// 			If authenticated request resource with Bearer token
	// 		If authenticated return response
	unauthenticatedResp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if unauthenticatedResp.StatusCode == http.StatusUnauthorized {
		defer unauthenticatedResp.Body.Close()
		asUri, ticket, err := getTicketInfo(unauthenticatedResp.Header.Get("WWW-Authenticate"))
		if err != nil {
			return nil, err
		}
		jsonBody, err := json.Marshal(claim{
			grantType:        "urn:ietf:params:oauth:grant-type:uma-ticket",
			ticket:           ticket,
			claimToken:       url.QueryEscape(aggregatorOwner),
			claimTokenFormat: "urn:solidlab:uma:claims:formats:webid",
		})
		if err != nil {
			return nil, err
		}
		authReps, err := client.Post(asUri+"/token", "application/json", bytes.NewReader(jsonBody))
		if err != nil {
			return nil, err
		}
		defer authReps.Body.Close()
		if authReps.StatusCode != http.StatusOK {
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Status:     http.StatusText(http.StatusUnauthorized),
				Header:     make(http.Header),
			}, nil
		}
		var asResponse map[string]string
		err = json.NewDecoder(authReps.Body).Decode(&asResponse)
		if err != nil {
			return nil, err
		}

		accessToken, ok := asResponse["access_token"]
		if !ok {
			return nil, fmt.Errorf("access_token not found in response")
		}
		tokenType, ok := asResponse["token_type"]
		if !ok {
			return nil, fmt.Errorf("token_type not found in response")
		}

		decodedToken, err := parseJwt(accessToken)
		if err != nil {
			return nil, err
		}

		req.Header.Set("Authorization", fmt.Sprintf("%s %s", tokenType, decodedToken))
		return client.Do(req)
	}
	// If the response is not unauthorized, return it as is
	fmt.Println("No authorization needed")
	return unauthenticatedResp, nil
}

func getTicketInfo(headerString string) (string, string, error) {
	header := strings.TrimPrefix(headerString, "Bearer ")
	params := strings.Split(header, ", ")
	var asUri string
	var ticket string
	for _, param := range params {
		keyValue := strings.Split(param, "=")
		if len(keyValue) != 2 {
			return "", "", fmt.Errorf("invalid parameter: %s", param)
		}
		key := strings.ReplaceAll(keyValue[0], "\"", "")
		value := strings.ReplaceAll(keyValue[1], "\"", "")
		switch key {
		case "as_uri":
			asUri = value
		case "ticket":
			ticket = value
		default:
			return "", "", fmt.Errorf("unknown parameter: %s", key)
		}
	}
	return asUri, ticket, nil
}

func parseJwt(token string) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	var payload map[string]interface{}
	err = json.Unmarshal(decoded, &payload)
	if err != nil {
		return nil, err
	}

	return payload, nil
}
