package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"aggregator/auth"
	"aggregator/model"
	"aggregator/services"

	"github.com/sirupsen/logrus"
)

type ServiceCollection struct {
	etagServices        int
	etagTransformations int
	services            map[string]model.Service
	serverMux           *http.ServeMux
}

func InitServiceCollection(mux *http.ServeMux) error {
	logrus.Debugf("Initialiazing service collection at %s", model.ServiceCollection)

	collection := ServiceCollection{
		etagServices:        0,
		etagTransformations: 0,
		services:            make(map[string]model.Service),
		serverMux:           mux,
	}

	if err := collection.HandleFunc(model.ServiceCollection, collection.HandleServicesEndpoint, []model.Scope{model.Read, model.Create}); err != nil {
		return fmt.Errorf("failed to add handler: %w", err)
	}

	logrus.Infof("Initialized service collection at %s", model.ServiceCollection)
	return nil
}

func (collec *ServiceCollection) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request), scopes []model.Scope) error {
	fullURL := model.BaseUrl + pattern

	// Register resource and define policies
	if err := auth.RegisterResource(fullURL, model.Owner.AuthzServerURL, scopes); err != nil {
		return fmt.Errorf("failed to register resource %s: %w", fullURL, err)
	}
	if err := auth.DefinePolicy(fullURL, model.Owner.UserId, model.Owner.AuthzServerURL, scopes); err != nil {
		return fmt.Errorf("failed to define policy for resource %s: %w", fullURL, err)
	}

	// Register HTTP handler
	collec.serverMux.HandleFunc(pattern, handler)
	logrus.Infof("Handler registered at %s", pattern)

	return nil
}

// HandleServicesEndpoint handles requests to the /<namespace>/services endpoint
func (collec *ServiceCollection) HandleServicesEndpoint(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "HEAD":
		collec.headServices(w, r)
	case "GET":
		collec.getServices(w, r)
	case "POST":
		collec.postService(w, r)
	default:
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
}

func (collec *ServiceCollection) headServices(w http.ResponseWriter, _ *http.Request) {
	header := w.Header()
	header.Set("Content-Type", "application/json")
	header.Set("ETag", strconv.Itoa(collec.etagServices))
	w.WriteHeader(http.StatusOK)
}

func (collec *ServiceCollection) getServices(w http.ResponseWriter, _ *http.Request) {
	//stream = rdfgo.NewStream()

	serviceList := []string{}
	for _, service := range collec.services {
		serviceList = append(serviceList, service.Exe.URI)
	}

	response := map[string][]string{
		"services": serviceList,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", strconv.Itoa(collec.etagServices))
	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		logrus.WithError(err).Error("Failed to encode service list")
		http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
		return
	}
}

// HandleServiceEndpoint handles requests to the /<service path> endpoint
func (collec *ServiceCollection) HandleServiceEndpoint(w http.ResponseWriter, r *http.Request) {
	id := strings.ReplaceAll(strings.Trim(r.URL.Path, "/"), "/", "-")
	service, ok := collec.services[id]
	if !ok {
		http.Error(w, "Service not found", http.StatusNotFound)
		return
	}

	switch r.Method {
	case "HEAD":
		collec.headService(w, r, service)
	case "GET":
		collec.getService(w, r, service)
	case "DELETE":
		collec.deleteService(w, r, service)
	default:
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

// generateServiceETag generates a consistent ETag based on the marshaled service data
func generateServiceETag(repr []byte) string {
	hash := sha256.Sum256(repr)
	return hex.EncodeToString(hash[:8]) // Use first 8 bytes for a shorter ETag
}

// headService HEAD /<namespace>/services/<id> returns the ETag header for the service with the given ID
func (collec *ServiceCollection) headService(w http.ResponseWriter, _ *http.Request, service model.Service) {
	logrus.WithFields(logrus.Fields{"service_id": service.ID}).Debug("Request HEAD for service")

	repr, err := service.FnORepresentation()
	if err != nil {
		logrus.WithError(err).Error("Failed to generate service FnO representation")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	header := w.Header()
	header.Set("Content-Type", "text/turtle")
	header.Set("ETag", generateServiceETag(repr))
	w.WriteHeader(http.StatusOK)
}

// getService GET /<service path> returns the service FnO representation for the service with the given ID
func (collec *ServiceCollection) getService(w http.ResponseWriter, _ *http.Request, service model.Service) {
	logrus.WithFields(logrus.Fields{"service_id": service.ID}).Info("Request GET for service")

	repr, err := service.FnORepresentation()
	if err != nil {
		logrus.WithError(err).Error("Failed to generate service FnO representation")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	header := w.Header()
	header.Set("Content-Type", "text/turtle")
	header.Set("ETag", generateServiceETag(repr))

	_, err = w.Write(repr)
	if err != nil {
		logrus.WithError(err).Error("Error writing service response body")
	}
}

func (collec *ServiceCollection) postService(w http.ResponseWriter, r *http.Request) {
	logrus.Info("Recieved request to register a service")

	var body string

	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/turtle") {
		// Handle Turtle content
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusInternalServerError)
			return
		}
		body = string(bodyBytes)
	} else {
		http.Error(w, "Unsupported Content-Type. Only text/turtle is supported", http.StatusUnsupportedMediaType)
		return
	}

	// Parse request description
	exe, err := services.ParseRequestBody(body)
	if err != nil {
		logrus.WithError(err).Errorf("Failed to parse body")
		http.Error(w, "Failed to parse body", http.StatusInternalServerError)
		return
	}

	// Extraxt service Id from execution URI
	servicePath, serviceId, err := services.ValidServiceUri(exe.URI)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid execution URI: %v", err), http.StatusBadRequest)
		return
	}

	if _, exists := collec.services[serviceId]; exists {
		http.Error(w, "Service id already registered for user", http.StatusConflict)
		return
	}

	// Create service
	service, err := services.CreateAggregatorService(serviceId, servicePath, exe)
	if err != nil {
		logrus.Error("Failed to create service from request")
		http.Error(w, fmt.Sprintf("Failed to create service from request: %v", err), http.StatusInternalServerError)
		return
	}

	// Store service
	collec.services[service.ID] = *service
	collec.etagServices++

	// Create service endpoint
	err = collec.HandleFunc(servicePath, collec.HandleServiceEndpoint, []model.Scope{model.Read, model.Delete})
	if err != nil {
		logrus.WithError(err).Errorf("Error registering handler for service %s", serviceId)
		return
	}

	// Return service information
	w.Header().Set("Content-Type", "text/turtle")

	repr, err := service.FnORepresentation()
	if err != nil {
		logrus.WithError(err).Error("Failed to generate service FnO representation")
		http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	_, err = w.Write(repr)
	if err != nil {
		logrus.WithError(err).Error("Error writing service FnO representation to response body")
		return
	}
}

// DELETE config deletes a service with the given ID
func (collec *ServiceCollection) deleteService(w http.ResponseWriter, _ *http.Request, service model.Service) {
	logrus.WithFields(logrus.Fields{"service_id": service.ID}).Info("Request to delete service")

	service.Stop()
	delete(collec.services, service.ID)

	collec.etagServices++
	w.WriteHeader(http.StatusOK)
}
