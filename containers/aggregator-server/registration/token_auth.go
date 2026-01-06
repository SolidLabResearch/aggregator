package registration

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	tokenAuthMethodClientSecretBasic = "client_secret_basic"
	tokenAuthMethodClientSecretPost  = "client_secret_post"
)

func doTokenRequest(endpoint string, supportedMethods []string, data url.Values, clientID string, clientSecret string) (*http.Response, error) {
	method := selectTokenAuthMethod(supportedMethods)
	req, err := buildTokenRequest(endpoint, method, data, clientID, clientSecret)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	return client.Do(req)
}

func selectTokenAuthMethod(supportedMethods []string) string {
	if len(supportedMethods) == 0 {
		return tokenAuthMethodClientSecretBasic
	}

	for _, method := range supportedMethods {
		switch strings.ToLower(method) {
		case tokenAuthMethodClientSecretBasic:
			return tokenAuthMethodClientSecretBasic
		case tokenAuthMethodClientSecretPost:
			return tokenAuthMethodClientSecretPost
		}
	}

	return tokenAuthMethodClientSecretBasic
}

func buildTokenRequest(endpoint string, authMethod string, data url.Values, clientID string, clientSecret string) (*http.Request, error) {
	if authMethod == "" {
		authMethod = tokenAuthMethodClientSecretBasic
	}

	switch authMethod {
	case tokenAuthMethodClientSecretPost:
		data.Set("client_id", clientID)
		data.Set("client_secret", clientSecret)
	case tokenAuthMethodClientSecretBasic:
		data.Del("client_id")
		data.Del("client_secret")
	default:
		return nil, fmt.Errorf("unsupported token auth method: %s", authMethod)
	}

	encoded := data.Encode()
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBufferString(encoded))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if authMethod == tokenAuthMethodClientSecretBasic {
		credentials := clientID + ":" + clientSecret
		basic := base64.StdEncoding.EncodeToString([]byte(credentials))
		req.Header.Set("Authorization", "Basic "+basic)
	}

	return req, nil
}
