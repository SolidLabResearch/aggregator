package model

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

var HttpClient = &http.Client{
	Transport: &localRedirectTransport{
		rt: http.DefaultTransport,
	},
	Timeout: 10 * time.Second,
}

// localRedirectTransport rewrites requests to localhost -> host.docker.internal
type localRedirectTransport struct {
	rt http.RoundTripper
}

func (t *localRedirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Rewrite localhost hostnames
	if strings.HasPrefix(req.URL.Host, "localhost") || strings.HasPrefix(req.URL.Host, "127.0.0.1") {
		// Keep the port if present
		host, port, _ := net.SplitHostPort(req.URL.Host)
		if host == "" {
			host = req.URL.Host
		}
		if port != "" {
			req.URL.Host = fmt.Sprintf("host.docker.internal:%s", port)
		} else {
			req.URL.Host = "host.docker.internal"
		}
	}

	// Optional: update the Host header so server sees correct host
	if req.Host == "" || req.Host == "localhost" || req.Host == "127.0.0.1" {
		req.Host = strings.Split(req.URL.Host, ":")[0]
	}

	return t.rt.RoundTrip(req)
}
