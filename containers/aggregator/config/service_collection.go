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
	"aggregator/util"

	"github.com/sirupsen/logrus"
)

type ServiceCollection struct {
	etagServices       int
	services           map[string]*model.Service
	servicesMu         sync.RWMutex
	routes             map[string]serviceRoute
	registeredPatterns map[string]bool
	serverMux          *http.ServeMux
}

type serviceRoute struct {
	serviceID  string
	forwardURL string
	methods    map[string]bool
}

func InitServiceCollection(mux *http.ServeMux) error {
	logrus.Debugf("Initialiazing service collection at %s", model.ServiceCollection)

	collection := ServiceCollection{
		etagServices:       0,
		services:           make(map[string]*model.Service),
		routes:             make(map[string]serviceRoute),
		registeredPatterns: make(map[string]bool),
		serverMux:          mux,
	}

	if err := collection.HandleFunc(model.ServiceCollection, collection.HandleServicesEndpoint, []model.Scope{model.Read, model.Create}); err != nil {
		return fmt.Errorf("failed to add handler: %w", err)
	}

	logrus.Infof("Initialized service collection at %s", model.ServiceCollection)
	return nil
}

func (collec *ServiceCollection) ensureServiceHandler(pattern string, scopes []model.Scope) error {
	collec.servicesMu.Lock()
	alreadyRegistered := collec.registeredPatterns[pattern]
	collec.servicesMu.Unlock()
	if alreadyRegistered {
		return nil
	}
	if err := collec.HandleFunc(pattern, collec.HandleServiceEndpoint, scopes); err != nil {
		return err
	}
	collec.servicesMu.Lock()
	collec.registeredPatterns[pattern] = true
	collec.servicesMu.Unlock()
	return nil
}

func (collec *ServiceCollection) setRoute(pattern string, route serviceRoute, scopes []model.Scope) error {
	collec.servicesMu.Lock()
	collec.routes[pattern] = route
	alreadyRegistered := collec.registeredPatterns[pattern]
	collec.servicesMu.Unlock()
	if alreadyRegistered {
		return nil
	}
	err := collec.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		collec.servicesMu.RLock()
		current, ok := collec.routes[r.URL.Path]
		_, serviceExists := collec.services[current.serviceID]
		collec.servicesMu.RUnlock()
		if !ok || !serviceExists {
			http.NotFound(w, r)
			return
		}
		if len(current.methods) > 0 && !current.methods[strings.ToUpper(r.Method)] {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		collec.HandleServiceOutput(w, r, current.forwardURL)
	}, scopes)
	if err != nil {
		collec.servicesMu.Lock()
		delete(collec.routes, pattern)
		collec.servicesMu.Unlock()
		return err
	}
	collec.servicesMu.Lock()
	collec.registeredPatterns[pattern] = true
	collec.servicesMu.Unlock()
	return nil
}

func (collec *ServiceCollection) removeServiceState(serviceID string) {
	collec.servicesMu.Lock()
	defer collec.servicesMu.Unlock()
	delete(collec.services, serviceID)
	for path, route := range collec.routes {
		if route.serviceID == serviceID {
			delete(collec.routes, path)
		}
	}
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
	collec.servicesMu.RLock()
	etag := collec.etagServices
	collec.servicesMu.RUnlock()
	header := w.Header()
	header.Set("Content-Type", "application/json")
	header.Set("ETag", strconv.Itoa(etag))
	w.WriteHeader(http.StatusOK)
}

func (collec *ServiceCollection) getServices(w http.ResponseWriter, _ *http.Request) {
	//stream = rdfgo.NewStream()

	serviceList := []string{}
	collec.servicesMu.RLock()
	for _, service := range collec.services {
		serviceList = append(serviceList, service.FullPath)
	}
	etag := collec.etagServices
	collec.servicesMu.RUnlock()

	response := map[string][]string{
		"services": serviceList,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", strconv.Itoa(etag))
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
	collec.servicesMu.RLock()
	service, ok := collec.services[id]
	collec.servicesMu.RUnlock()
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
	var err error

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}

	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/turtle") {
		body = string(bodyBytes)
	} else if strings.Contains(contentType, "application/ld+json") {
		// Convert JSON-LD into support n-quads format
		body, err = util.JsonLDToNQuads(bodyBytes)
		if err != nil {
			http.Error(w, "Invalid JSON-LD request", http.StatusBadRequest)
			logrus.WithError(err).Error("Failed to convert JSON-LD to N_Quads")
			return
		}
		contentType = "application/n-quads"
	} else {
		http.Error(w, "Unsupported Content-Type", http.StatusUnsupportedMediaType)
		return
	}

	// Parse request description
	service, err := services.ParseRequestBody(body, contentType)
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
	service.KubernetesName = services.NewKubernetesName()

	// Create service
	err = services.DeployAggregatorService(service)
	if err != nil {
		logrus.WithError(err).Error("Failed to deploy service from request")
		http.Error(w, "Failed to deploy service", http.StatusInternalServerError)
		return
	}
	if err := service.InitDescription(); err != nil {
		_ = service.Stop()
		logrus.WithError(err).Error("Failed to initialize service description")
		http.Error(w, "Failed to initialize service description", http.StatusInternalServerError)
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
	rollback := func() {
		collec.removeServiceState(service.InstanceID)
		if cleanupErr := service.Stop(); cleanupErr != nil {
			logrus.WithError(cleanupErr).Warn("Failed to roll back deployed service")
		}
	}

	// Create service endpoint
	err = collec.ensureServiceHandler(aggPath, []model.Scope{model.Read, model.Delete})
	if err != nil {
		logrus.WithError(err).Errorf("Error registering handler for service %s", serviceId)
		http.Error(w, "Failed to create service from request", http.StatusInternalServerError)
		rollback()
		return
	}

	// Create dataset distribution endpoints
	seen := make(map[string]bool)

	for datasetID, dataset := range service.Deployment.Definition.Datasets {
		for distributionID, distribution := range dataset.Distributions {
			externalPath := distribution.Path
			if externalPath == "" {
				errMsg := fmt.Sprintf("path is required for dataset %s distribution %s", datasetID, distributionID)
				logrus.Error(errMsg)
				http.Error(w, errMsg, http.StatusInternalServerError)
				rollback()
				return
			}

			path := util.JoinPaths(aggPath, externalPath)

			if seen[path] {
				errMsg := fmt.Sprintf("duplicate externalPath resolved to %s", path)
				logrus.Error(errMsg)
				http.Error(w, errMsg, http.StatusInternalServerError)
				rollback()
				return
			}
			seen[path] = true

			// Build forward URL at registration time, nil if abstract
			var forwardURL string
			{
				internalPath := distribution.Target.InternalPath
				if internalPath == "" {
					internalPath = "/"
				}
				if !strings.HasPrefix(internalPath, "/") {
					internalPath = "/" + internalPath
				}
				forwardURL = fmt.Sprintf(
					"%s://%s.%s.svc.cluster.local:%d%s",
					"http",
					services.ResourceKubernetesName(service.KubernetesName, distribution.Target.Resource),
					model.Namespace,
					distribution.Target.Port,
					internalPath,
				)
			}

			err = collec.setRoute(path, serviceRoute{serviceID: service.InstanceID, forwardURL: forwardURL}, []model.Scope{model.Read, model.Write})
			if err != nil {
				logrus.WithError(err).Errorf("Error registering handler for dataset %s", datasetID)
				http.Error(w, "Failed to create service from request", http.StatusInternalServerError)
				rollback()
				return
			}

			logrus.Infof("Registered dataset endpoint: %s/%s → %s", datasetID, distributionID, path)
		}
	}

	for endpointID, endpoint := range service.Deployment.Definition.Endpoints {
		path := util.JoinPaths(aggPath, endpoint.Path)
		if seen[path] {
			errMsg := fmt.Sprintf("duplicate endpoint path resolved to %s", path)
			logrus.Error(errMsg)
			http.Error(w, errMsg, http.StatusInternalServerError)
			rollback()
			return
		}
		seen[path] = true
		methods := map[string]bool{}
		for _, operation := range endpoint.Operations {
			methods[strings.ToUpper(operation.Method)] = true
		}
		internalPath := endpoint.Target.InternalPath
		if internalPath == "" {
			internalPath = "/"
		}
		forwardURL := fmt.Sprintf("http://%s.%s.svc.cluster.local:%d%s",
			services.ResourceKubernetesName(service.KubernetesName, endpoint.Target.Resource),
			model.Namespace, endpoint.Target.Port, internalPath)
		err = collec.setRoute(path, serviceRoute{serviceID: service.InstanceID, forwardURL: forwardURL, methods: methods}, []model.Scope{model.Read, model.Write})
		if err != nil {
			logrus.WithError(err).Errorf("Error registering operational endpoint %s", endpointID)
			http.Error(w, "Failed to create service endpoint", http.StatusInternalServerError)
			rollback()
			return
		}
		logrus.Infof("Registered operational endpoint: %s → %s", endpointID, path)
	}

	// Return service information
	w.Header().Set("Content-Type", "text/turtle")
	w.Header().Set("Location", service.FullPath)

	repr, err := service.Description.FnORepresentation()
	if err != nil {
		logrus.WithError(err).Error("Failed to generate service FnO representation")
		http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
		rollback()
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

	collec.removeServiceState(service.InstanceID)
	collec.servicesMu.Lock()
	collec.etagServices++
	collec.servicesMu.Unlock()
	w.WriteHeader(http.StatusOK)
}

// Handles all incoming service requests <service path>/<output>
func (collec *ServiceCollection) HandleServiceOutput(w http.ResponseWriter, r *http.Request, forwardURL string) {
	if forwardURL == "" {
		http.Error(w, "Output has no distribution", http.StatusNotFound)
		return
	}

	req, err := http.NewRequest(r.Method, forwardURL, r.Body)
	if err != nil {
		logrus.WithError(err).Error("Failed to create forward request")
		http.Error(w, "Failed to reach requested service", http.StatusInternalServerError)
		return
	}

	for k, vv := range r.Header {
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}

	resp, err := model.HttpClient.Do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to forward request: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	w.WriteHeader(resp.StatusCode)

	if _, err := io.Copy(w, resp.Body); err != nil {
		logrus.WithError(err).Error("Failed to copy response body")
	}
}
