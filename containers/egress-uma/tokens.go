package main

import (
	"egress-uma/model"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/sirupsen/logrus"
)

func getAccessToken() (string, error) {
	log := logrus.WithFields(logrus.Fields{
		"user_id":   UserId,
		"component": "token_service",
	})

	// URL-encode the userID for safe use as a query parameter
	encodedID := url.QueryEscape(UserId)

	url := fmt.Sprintf(
		"http://token-service:8080/token?id=%s",
		encodedID,
	)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	resp, err := model.HttpClient.Do(req)
	if err != nil {
		log.WithError(err).Error("Failed to contact token service")
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.WithField("status_code", resp.StatusCode).
			Error("Token service returned error")
		return "", fmt.Errorf("token service returned %d", resp.StatusCode)
	}

	var body struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		log.WithError(err).Error("Failed to decode token service response")
		return "", err
	}

	if body.AccessToken == "" {
		return "", errors.New("no access_token returned from token service")
	}

	return body.AccessToken, nil
}
