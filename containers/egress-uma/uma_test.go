package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

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
