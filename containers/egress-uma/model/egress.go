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
		rt: &http.Transport{
			DisableCompression:  true,
			ForceAttemptHTTP2:   false,
			MaxIdleConns:        100,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	},
	Timeout: 0,
}

type localRedirectTransport struct {
	rt http.RoundTripper
}

func (t *localRedirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.HasPrefix(req.URL.Host, "localhost") || strings.HasPrefix(req.URL.Host, "127.0.0.1") {
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

	if req.Host == "" || req.Host == "localhost" || req.Host == "127.0.0.1" {
		req.Host = strings.Split(req.URL.Host, ":")[0]
	}

	return t.rt.RoundTrip(req)
}
