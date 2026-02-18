package registration

import (
	"aggregator/model"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
	Expiry       int64  `json:"expiry"`
}

func storeTokens(
	userID string,
	tok TokenResponse,
	issuer string,
	clientID string,
	clientSecret string,
) error {

	expiryUnix := time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second).Unix()

	reqBody := StoreRequest{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		IDToken:      tok.IDToken,
		Issuer:       issuer,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Expiry:       expiryUnix,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	url := fmt.Sprintf(
		"http://token-service.%s.svc.cluster.local:8080/token/%s",
		model.Namespace,
		userID,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := model.HttpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("token service returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func updateTokens(
	userID string,
	tok TokenResponse,
	issuer string,
	clientID string,
	clientSecret string,
) error {
	expiryUnix := time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second).Unix()

	reqBody := StoreRequest{
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

	url := fmt.Sprintf(
		"http://token-service.%s.svc.cluster.local:8080/token/%s",
		model.Namespace,
		userID,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := model.HttpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("token service returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
