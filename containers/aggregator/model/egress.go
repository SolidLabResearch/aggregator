package model

import "net/http"

type rewriteLocalhostTransport struct {
	base *http.Transport
}

func (t *rewriteLocalhostTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Hostname()
	port := req.URL.Port()

	if host == "localhost" || host == "127.0.0.1" {
		newHost := "host.docker.internal"
		if port != "" {
			req.URL.Host = newHost + ":" + port
		} else {
			req.URL.Host = newHost
		}

		// Optional: ensure Host header matches
		req.Host = newHost
	}

	return t.base.RoundTrip(req)
}
