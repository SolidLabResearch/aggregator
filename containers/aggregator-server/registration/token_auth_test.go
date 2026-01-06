package registration

import (
	"io"
	"net/url"
	"strings"
	"testing"
)

func TestSelectTokenAuthMethod_DefaultsToBasicWhenEmpty(t *testing.T) {
	method := selectTokenAuthMethod(nil)
	if method != tokenAuthMethodClientSecretBasic {
		t.Fatalf("Expected %s, got %s", tokenAuthMethodClientSecretBasic, method)
	}
}

func TestSelectTokenAuthMethod_UsesFirstSupported(t *testing.T) {
	method := selectTokenAuthMethod([]string{"client_secret_post", "client_secret_basic"})
	if method != tokenAuthMethodClientSecretPost {
		t.Fatalf("Expected %s, got %s", tokenAuthMethodClientSecretPost, method)
	}
}

func TestSelectTokenAuthMethod_SkipsUnsupported(t *testing.T) {
	method := selectTokenAuthMethod([]string{"unsupported", "client_secret_basic"})
	if method != tokenAuthMethodClientSecretBasic {
		t.Fatalf("Expected %s, got %s", tokenAuthMethodClientSecretBasic, method)
	}
}

func TestBuildTokenRequest_ClientSecretPost(t *testing.T) {
	data := url.Values{"grant_type": {"client_credentials"}}
	req, err := buildTokenRequest("https://idp.example/token", tokenAuthMethodClientSecretPost, data, "client", "secret")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("Expected no Authorization header, got %s", got)
	}

	body, _ := io.ReadAll(req.Body)
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "client_id=client") || !strings.Contains(bodyStr, "client_secret=secret") {
		t.Fatalf("Expected client credentials in body, got %s", bodyStr)
	}
}

func TestBuildTokenRequest_ClientSecretBasic(t *testing.T) {
	data := url.Values{"grant_type": {"client_credentials"}}
	req, err := buildTokenRequest("https://idp.example/token", tokenAuthMethodClientSecretBasic, data, "client", "secret")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	auth := req.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Basic ") {
		t.Fatalf("Expected Basic auth header, got %s", auth)
	}

	body, _ := io.ReadAll(req.Body)
	bodyStr := string(body)
	if strings.Contains(bodyStr, "client_id=") || strings.Contains(bodyStr, "client_secret=") {
		t.Fatalf("Expected no client credentials in body, got %s", bodyStr)
	}
}
