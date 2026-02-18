package ingress

import (
	"aggregator/model"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// Middleware is a function that wraps an http.Handler
type Middleware func(http.Handler) http.Handler

// Chain applies multiple middlewares in order
func Chain(h http.Handler, mws ...Middleware) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// UmaAuthMiddleware returns a middleware that performs UMA authorization
func UMAAuthMiddleware() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// No authenticaton needed if no authorization server is provided
			if model.Owner.AuthzServerURL == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Build resource ID for UMA lookup
			host := r.Host
			path := r.URL.Path
			resourceID := fmt.Sprintf("%s://%s%s", model.Protocol, host, path)

			// Create UMA request
			payload := map[string]string{
				"resource_id": resourceID,
				"method":      r.Method,
			}
			data, err := json.Marshal(payload)
			if err != nil {
				logrus.Errorf("Error creating UMA request: %v", err)
				http.Error(w, "Authorization service error", http.StatusInternalServerError)
				return
			}

			req, err := http.NewRequest(
				"POST",
				fmt.Sprintf("http://ingress-uma.%s.svc.cluster.local:8080/authorize", model.Namespace),
				bytes.NewReader(data),
			)
			if err != nil {
				logrus.Errorf("Error creating UMA request: %v", err)
				http.Error(w, "Authorization service error", http.StatusInternalServerError)
				return
			}
			req.Header.Set("Content-Type", "application/json")

			// Forward the Authorization header (Bearer token)
			if token := r.Header.Get("Authorization"); token != "" {
				req.Header.Set("Authorization", token)
			}

			// Call UMA service
			resp, err := model.HttpClient.Do(req)
			if err != nil {
				log.Printf("Error calling UMA service: %v", err)
				http.Error(w, "Authorization service error", http.StatusInternalServerError)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				// Unauthorized: return UMA response headers/status to client
				for k, v := range resp.Header {
					for _, vv := range v {
						w.Header().Add(k, vv)
					}
				}
				w.WriteHeader(resp.StatusCode)
				return
			}

			// Authorized: let request pass through
			next.ServeHTTP(w, r)
		})
	}
}

// StripPrefixMiddleware returns a middleware that strips the given prefix from the path
func StripPrefixMiddleware(prefix string) Middleware {
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, prefix) {
				r.URL.Path = strings.TrimPrefix(r.URL.Path, prefix)
				if r.URL.Path == "" {
					r.URL.Path = "/" // avoid empty path
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func LoggingMiddleware() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Call the next handler
			next.ServeHTTP(w, r)

			// Log after the request has been processed
			log.Printf(
				"%s %s%s from %s | UA=%s | duration=%s",
				r.Method,
				r.URL.Path,
				func() string {
					if r.URL.RawQuery != "" {
						return "?" + r.URL.RawQuery
					}
					return ""
				}(),
				r.RemoteAddr,
				r.UserAgent(),
				time.Since(start),
			)
		})
	}
}
