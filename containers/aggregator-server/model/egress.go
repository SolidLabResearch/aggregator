package model

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
)

// localRedirectTransport rewrites requests to localhost -> host.docker.internal
type localRedirectTransport struct {
	rt http.RoundTripper
}

func (t *localRedirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	log := logrus.WithFields(logrus.Fields{
		"component": "local_redirect_transport",
		"method":    req.Method,
		"url":       req.URL.String(),
	})

	originalHost := req.URL.Host
	rewritten := false

	// Rewrite localhost hostnames
	if strings.HasPrefix(req.URL.Host, "localhost") ||
		strings.HasPrefix(req.URL.Host, "127.0.0.1") {

		_, port, err := net.SplitHostPort(req.URL.Host)
		if err != nil {
			log.WithError(err).Debug("No port detected in host")
		}

		if port != "" {
			req.URL.Host = fmt.Sprintf("host.docker.internal:%s", port)
		} else {
			req.URL.Host = "host.docker.internal"
		}

		rewritten = true
	}

	// Optional: update the Host header
	if req.Host == "" || req.Host == "localhost" || req.Host == "127.0.0.1" {
		oldHostHeader := req.Host
		req.Host = strings.Split(req.URL.Host, ":")[0]

		log.WithFields(logrus.Fields{
			"old_host_header": oldHostHeader,
			"new_host_header": req.Host,
		}).Debug("Updated request Host header")
	}

	if rewritten {
		log.WithFields(logrus.Fields{
			"original_host":  originalHost,
			"rewritten_host": req.URL.Host,
		}).Debug("Rewrote localhost request to host.docker.internal")
	}

	// Execute request
	resp, err := t.rt.RoundTrip(req)
	if err != nil {
		log.WithError(err).
			WithField("target_host", req.URL.Host).
			Error("HTTP round trip failed")
		return nil, err
	}

	log.WithFields(logrus.Fields{
		"status_code": resp.StatusCode,
		"target_host": req.URL.Host,
	}).Debug("HTTP round trip completed")

	return resp, nil
}
