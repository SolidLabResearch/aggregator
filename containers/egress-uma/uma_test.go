package main

import (
	"egress-uma/model"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func response(status int, body string, headers http.Header) *http.Response {
	if headers == nil {
		headers = make(http.Header)
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: headers}
}

type captureRoundTripper struct {
	mu       sync.Mutex
	requests []*http.Request
}

func (c *captureRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	c.requests = append(c.requests, req)
	c.mu.Unlock()

	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("ok")),
		Header:     make(http.Header),
	}, nil
}

func (c *captureRoundTripper) firstRequest() *http.Request {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.requests) == 0 {
		return nil
	}
	return c.requests[0]
}

func TestRequestWithUMA_PreservesScheme(t *testing.T) {
	rt := &captureRoundTripper{}
	client := &http.Client{Transport: rt}

	req := httptest.NewRequest(http.MethodGet, "http://rs.local:3000/bob/favorites?x=1", nil)
	resp, err := RequestWithUMA(client, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer resp.Body.Close()

	first := rt.firstRequest()
	if first == nil {
		t.Fatal("expected request to be sent")
	}
	if first.URL.Scheme != "http" {
		t.Fatalf("expected http scheme, got %q", first.URL.Scheme)
	}
	if first.URL.Host != "rs.local:3000" {
		t.Fatalf("expected host rs.local:3000, got %q", first.URL.Host)
	}
}

func TestRequestWithUMA_UsesMatchingBearerChallengeAsFallback(t *testing.T) {
	oldOIDCServer, oldAggregatorID, oldHTTPClient := OIDCServer, AggregatorID, model.HttpClient
	t.Cleanup(func() {
		OIDCServer, AggregatorID, model.HttpClient = oldOIDCServer, oldAggregatorID, oldHTTPClient
	})
	OIDCServer = "https://auth.example/realms/kvasir/"
	AggregatorID = "aggregator-1"
	model.HttpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != "token-service:8080" {
			t.Fatalf("unexpected token client request to %s", req.URL)
		}
		return response(http.StatusOK, `{"access_token":"aggregator-token"}`, nil), nil
	})}

	requests := 0
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		if requests == 1 {
			header := make(http.Header)
			header.Set("WWW-Authenticate", `Bearer as_uri="https://auth.example/realms/kvasir"`)
			return response(http.StatusUnauthorized, "unauthorized", header), nil
		}
		if got := req.Header.Get("Authorization"); got != "Bearer aggregator-token" {
			t.Fatalf("expected aggregator bearer token, got %q", got)
		}
		return response(http.StatusOK, "ok", nil), nil
	})}

	req := httptest.NewRequest(http.MethodGet, "https://resource.example/data", nil)
	resp, err := RequestWithUMA(client, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer resp.Body.Close()
	if requests != 2 {
		t.Fatalf("expected initial request and bearer retry, got %d requests", requests)
	}
}

func TestRequestWithUMA_RejectsBearerChallengeFromDifferentIssuer(t *testing.T) {
	oldOIDCServer := OIDCServer
	OIDCServer = "https://auth.example/realms/kvasir"
	t.Cleanup(func() { OIDCServer = oldOIDCServer })

	requests := 0
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		header := make(http.Header)
		header.Set("WWW-Authenticate", `Bearer as_uri="https://attacker.example"`)
		return response(http.StatusUnauthorized, "unauthorized", header), nil
	})}

	req := httptest.NewRequest(http.MethodGet, "https://resource.example/data", nil)
	if _, err := RequestWithUMA(client, req); err == nil {
		t.Fatal("expected issuer mismatch error")
	}
	if requests != 1 {
		t.Fatalf("expected no bearer retry, got %d requests", requests)
	}
}

func TestParseAuthenticateChallenge(t *testing.T) {
	tests := []struct {
		header string
		want   authenticateChallenge
	}{
		{`Bearer as_uri="https://auth.example/realms/kvasir"`, authenticateChallenge{Scheme: "Bearer", ASURI: "https://auth.example/realms/kvasir"}},
		{`UMA realm="solid", as_uri="https://uma.example/uma", ticket="ticket-1"`, authenticateChallenge{Scheme: "UMA", ASURI: "https://uma.example/uma", Ticket: "ticket-1"}},
	}
	for _, test := range tests {
		if got := parseAuthenticateChallenge(test.header); got != test.want {
			t.Errorf("parseAuthenticateChallenge(%q) = %#v, want %#v", test.header, got, test.want)
		}
	}
}
