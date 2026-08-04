package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
)

// RegisterPublicHandlers exposes only the RDF catalogs intended for clients.
func (r *Registry) RegisterPublicHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/profiles", r.handleProfiles)
	mux.HandleFunc("/profiles/", r.handleProfiles)
	mux.HandleFunc("/deployments", r.handleDeployments)
	mux.HandleFunc("/deployments/", r.handleDeployments)
}

// RegisterInternalHandlers exposes the orchestration bundle API. Callers should
// mount this on the cluster-only listener, never on the public ingress listener.
func (r *Registry) RegisterInternalHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/internal/deployment-functions/", r.handleInternalBundle)
}

func (r *Registry) handleProfiles(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimPrefix(request.URL.Path, "/profiles/")
	var body []byte
	if request.URL.Path == "/profiles" {
		body = r.ProfileCatalog()
	} else if name != "" {
		var ok bool
		body, ok = r.ProfileRDF(name)
		if !ok {
			http.NotFound(w, request)
			return
		}
	} else {
		http.NotFound(w, request)
		return
	}
	writeRDF(w, request, body)
}

func (r *Registry) handleDeployments(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimPrefix(request.URL.Path, "/deployments/")
	var body []byte
	if request.URL.Path == "/deployments" {
		body = r.DeploymentCatalog()
	} else if name != "" {
		var ok bool
		body, ok = r.DeploymentRDF(name)
		if !ok {
			http.NotFound(w, request)
			return
		}
	} else {
		http.NotFound(w, request)
		return
	}
	writeRDF(w, request, body)
}

func (r *Registry) handleInternalBundle(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimPrefix(request.URL.Path, "/internal/deployment-functions/")
	if name == "" || strings.Contains(name, "/") {
		http.NotFound(w, request)
		return
	}
	body, etag, ok := r.BundleDocument(name)
	if !ok {
		http.NotFound(w, request)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("ETag", etag)
	if request.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if request.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, _ = w.Write(body)
}

func writeRDF(w http.ResponseWriter, request *http.Request, body []byte) {
	hash := sha256.Sum256(body)
	w.Header().Set("Content-Type", "text/turtle")
	w.Header().Set("ETag", `"`+hex.EncodeToString(hash[:8])+`"`)
	if request.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, _ = w.Write(body)
}
