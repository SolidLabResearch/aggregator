package registration

import (
	"aggregator/model"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

type StoreRequest struct {
	AggregatorID string `json:"aggregator_id"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
	Expiry       int64  `json:"expiry"`
}

func upsertTokens(
	aggregatorID string,
	tok TokenResponse,
	issuer string,
	clientID string,
	clientSecret string,
) error {
	expiryUnix := time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second).Unix()

	reqBody := StoreRequest{
		AggregatorID: aggregatorID,
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		IDToken:      tok.IDToken,
		Expiry:       expiryUnix,
		Issuer:       issuer,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, "http://token-service:8080/token", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := model.HttpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("token service returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func deleteTokens(aggregatorID string) error {
	encodedID := url.QueryEscape(aggregatorID)

	endpoint := fmt.Sprintf(
		"http://token-service:8080/token?id=%s",
		encodedID,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return err
	}

	resp, err := model.HttpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent &&
		resp.StatusCode != http.StatusOK &&
		resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("unexpected status from token service: %d", resp.StatusCode)
	}

	return nil
}
