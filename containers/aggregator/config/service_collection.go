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
	"sync"

	"aggregator/auth"
	"aggregator/model"
	"aggregator/services"

	"github.com/sirupsen/logrus"
)

type ServiceCollection struct {
	etagServices        int
	etagTransformations int
	services            map[string]*model.Service
	servicesMu          sync.RWMutex
	serverMux           *http.ServeMux
}

func InitServiceCollection(mux *http.ServeMux) error {
	logrus.Debugf("Initialiazing service collection at %s", model.ServiceCollection)

	collection := ServiceCollection{
		etagServices:        0,
		etagTransformations: 0,
		services:            make(map[string]*model.Service),
		serverMux:           mux,
	}

	if err := collection.HandleFunc(model.ServiceCollection, collection.HandleServicesEndpoint, []model.Scope{model.Read, model.Create}); err != nil {
		return fmt.Errorf("failed to add handler: %w", err)
	}

	logrus.Infof("Initialized service collection at %s", model.ServiceCollection)
	return nil
}

func (collec *ServiceCollection) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request), scopes []model.Scope) error {
	fullURL := model.ExternalBaseURL() + pattern

	// Register resource and define policies
	if err := auth.RegisterResource(fullURL, scopes); err != nil {
		return fmt.Errorf("failed to register resource %s: %w", fullURL, err)
	}
	if err := auth.DefinePolicy(fullURL, scopes); err != nil {
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
		serviceList = append(serviceList, service.FullPath)
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
		collec.headService(w, r, *service)
	case "GET":
		collec.getService(w, r, *service)
	case "DELETE":
		collec.deleteService(w, r, *service)
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
	logrus.WithFields(logrus.Fields{"service_id": service.InstanceID}).Debug("Request HEAD for service")

	repr, err := service.Description.FnORepresentation()
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
	logrus.WithFields(logrus.Fields{"service_id": service.InstanceID}).Info("Request GET for service")

	repr, err := service.Description.FnORepresentation()
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
	service, err := services.ParseRequestBody(body)
	if err != nil {
		logrus.WithError(err).Errorf("Failed to parse body")
		http.Error(w, "Failed to parse body", http.StatusInternalServerError)
		return
	}

	// Extraxt service Path and Id
	aggPath, serviceId, err := services.ValidServicePath(service.FullPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid execution URI: %v", err), http.StatusBadRequest)
		return
	}

	// Check if service ID already exists
	collec.servicesMu.Lock()
	if _, exists := collec.services[serviceId]; exists {
		collec.servicesMu.Unlock()
		http.Error(w, "Service id already registered for user", http.StatusConflict)
		return
	}
	collec.servicesMu.Unlock()

	service.AggPath = aggPath
	service.InstanceID = serviceId
	service.NamespaceID = serviceId + "-" + model.ID

	// Create service
	err = services.DeployAggregatorService(service)
	if err != nil {
		logrus.WithError(err).Error("Failed to deploy service from request")
		http.Error(w, "Failed to deploy service", http.StatusInternalServerError)
		return
	}

	// Store service and update ETag
	collec.servicesMu.Lock()
	if _, exists := collec.services[serviceId]; exists {
		collec.servicesMu.Unlock()
		http.Error(w, "Service id already registered for user", http.StatusConflict)
		service.Stop()
		return
	}

	collec.services[service.InstanceID] = service
	collec.etagServices++
	collec.servicesMu.Unlock()

	// Create service endpoint
	err = collec.HandleFunc(aggPath, collec.HandleServiceEndpoint, []model.Scope{model.Read, model.Delete})
	if err != nil {
		logrus.WithError(err).Errorf("Error registering handler for service %s", serviceId)
		http.Error(w, "Failed to create service from request", http.StatusInternalServerError)
		return
	}

	// Create output endpoints
	for pred := range service.Application.Transformation.OutputMapping {
		path := aggPath + "/" + pred
		predUri := service.Application.Transformation.Base + pred
		outputUri, exists := service.Application.Transformation.Predicates[predUri]
		if !exists {
			logrus.Errorf("No output found for mapped predicate %s", predUri)
			http.Error(w, "Failed to create service from request", http.StatusInternalServerError)
			return
		}

		err = collec.HandleFunc(path, collec.HandleServiceOutput, []model.Scope{model.Read, model.Write})
		if err != nil {
			logrus.WithError(err).Errorf("Error registering handler for output %s", outputUri)
			http.Error(w, "Failed to create service from request", http.StatusInternalServerError)
			return
		}
	}

	// Return service information
	w.Header().Set("Content-Type", "text/turtle")

	service.InitDescription()
	repr, err := service.Description.FnORepresentation()
	if err != nil {
		logrus.WithError(err).Error("Failed to generate service FnO representation")
		http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	_, err = w.Write(repr)
	if err != nil {
		logrus.WithError(err).Error("Error writing service FnO representation to response body")
		http.Error(w, "Failed to write response", http.StatusInternalServerError)
		return
	}
}

// DELETE config deletes a service with the given ID
func (collec *ServiceCollection) deleteService(w http.ResponseWriter, _ *http.Request, service model.Service) {
	logrus.WithFields(logrus.Fields{"service_id": service.InstanceID}).Info("Request to delete service")

	err := service.Stop()
	if err != nil {
		logrus.WithError(err).Error("Failed to stop service")
		http.Error(w, "Failed to stop service", http.StatusInternalServerError)
		return
	}

	delete(collec.services, service.InstanceID)

	collec.etagServices++
	w.WriteHeader(http.StatusOK)
}

// Handles all incoming service requests <service path>/<output>
func (collec *ServiceCollection) HandleServiceOutput(w http.ResponseWriter, r *http.Request) {
	// Trim leading/trailing slashes and split path
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 2 {
		http.Error(w, "Invalid path, must be /<service-path>/<output>", http.StatusBadRequest)
		return
	}

	// Last segment is the output
	pred := parts[len(parts)-1]

	// Everything else is the service path
	servicePath := parts[:len(parts)-1]
	serviceID := strings.Join(servicePath, "-")
	service, ok := collec.services[serviceID]
	if !ok {
		http.Error(w, "Service not found", http.StatusNotFound)
		return
	}

	mapping, exists := service.Application.Transformation.OutputMapping[pred]
	if !exists {
		logrus.Errorf("No output mapping found for %s", pred)
		http.Error(w, fmt.Sprintf("Requested service has no output %s", pred), http.StatusNotFound)
		return
	}

	// Create new request to forward
	forwardURL := fmt.Sprintf("http://%s.%s.svc.cluster.local:%d%s",
		service.NamespaceID,
		model.Namespace,
		mapping.Port,
		mapping.Path,
	)
	req, err := http.NewRequest(r.Method, forwardURL, r.Body)
	if err != nil {
		logrus.WithError(err).Error("Failed to create forward request")
		http.Error(w, "Failed to reach requested service", http.StatusInternalServerError)
		return
	}

	// Copy headers from original request
	for k, vv := range r.Header {
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}

	// Send request using proxy client
	resp, err := model.HttpClient.Do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to forward request: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	// Write status code
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	if _, err := io.Copy(w, resp.Body); err != nil {
		logrus.WithError(err).Error("Failed to copy response body")
	}
}
