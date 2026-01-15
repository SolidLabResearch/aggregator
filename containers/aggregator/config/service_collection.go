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
	"time"

	"aggregator/auth"
	"aggregator/model"
	"aggregator/services"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type UserConfigData struct {
	owner               model.User
	etagServices        int
	etagTransformations int
	services            map[string]*model.Service
	serveMux            *http.ServeMux
	servicesMu          sync.RWMutex
}

func InitUserConfiguration(mux *http.ServeMux, user model.User) error {
	config := UserConfigData{
		owner:               user,
		etagServices:        0,
		etagTransformations: 0,
		services:            make(map[string]*model.Service),
		serveMux:            mux,
	}

	pattern := fmt.Sprintf("/config/%s/services", user.Namespace)
	if err := config.HandleFunc(pattern, config.HandleServicesEndpoint, []model.Scope{model.Read, model.Create}); err != nil {
		logrus.WithError(err).Errorf("Failed to initialize user configuration endpoint '%s'", pattern)
		return fmt.Errorf("initUserConfiguration: failed to register handler for %s: %w", pattern, err)
	}

	logrus.Infof("User configuration endpoint initialized for user %s at %s", user.UserId, pattern)
	return nil
}

func (config *UserConfigData) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request), scopes []model.Scope) error {
	fullURL := fmt.Sprintf("%s://%s%s", model.Protocol, model.ExternalHost, pattern)
	logrus.Debugf("Registering handler for pattern '%s' at URL '%s'", pattern, fullURL)

	if err := auth.RegisterResource(fullURL, config.owner.AuthzServerURL, scopes); err != nil {
		return fmt.Errorf("failed to register resource %s: %w", fullURL, err)
	}
	if err := auth.DefinePolicy(fullURL, config.owner.UserId, config.owner.AuthzServerURL, scopes); err != nil {
		return fmt.Errorf("failed to define policy for %s: %w", fullURL, err)
	}

	// Register HTTP handler
	config.serveMux.HandleFunc(pattern, handler)
	logrus.Infof("Handler registered for pattern: %s", pattern)

	logrus.Info("HandleFunc setup completed for pattern: ", pattern)
	return nil
}

// HandleServicesEndpoint handles requests to the /config/<namespace>/services endpoint
func (config *UserConfigData) HandleServicesEndpoint(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "HEAD":
		config.headServices(w, r)
	case "GET":
		config.getServices(w, r)
	case "POST":
		config.postService(w, r)
	default:
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
}

func (config *UserConfigData) headServices(w http.ResponseWriter, _ *http.Request) {
	header := w.Header()
	header.Set("Content-Type", "application/json")
	header.Set("ETag", strconv.Itoa(config.etagServices))
	w.WriteHeader(http.StatusOK)
}

func (config *UserConfigData) getServices(w http.ResponseWriter, _ *http.Request) {
	serviceList := []string{}
	config.servicesMu.RLock()
	for _, service := range config.services {
		if service == nil {
			continue
		}
		url := fmt.Sprintf("%s://%s/config/%s/services/%s", model.Protocol, model.ExternalHost, service.Namespace, service.Id)
		serviceList = append(serviceList, url)
	}
	config.servicesMu.RUnlock()

	response := map[string][]string{
		"services": serviceList,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", strconv.Itoa(config.etagServices))
	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		logrus.WithError(err).Error("Failed to encode service list")
		http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
		return
	}
}

func (config *UserConfigData) postService(w http.ResponseWriter, r *http.Request) {
	logrus.Info("Recieved request to register a service")

	var request model.ServiceRequest

	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/turtle") {
		// Handle Turtle content
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusInternalServerError)
			return
		}
		request.Description = string(bodyBytes)
	} else {
		http.Error(w, "Unsupported Content-Type. Only text/turtle is supported", http.StatusUnsupportedMediaType)
		return
	}

	// add request metadata
	request.Owner = config.owner
	if request.Id == "" {
		request.Id = uuid.NewString()
	}

	config.servicesMu.RLock()
	_, exists := config.services[request.Id]
	config.servicesMu.RUnlock()
	if exists {
		http.Error(w, "Service id already registered for user", http.StatusConflict)
		return
	}

	// create service
	service, err := services.CreateService(request)
	if err != nil {
		logrus.WithError(err).Error("Failed to create service")
		http.Error(w, fmt.Sprintf("Failed to create service: %v", err), http.StatusInternalServerError)
		return
	}

	// Store service
	config.servicesMu.Lock()
	config.services[request.Id] = service
	config.servicesMu.Unlock()
	config.etagServices++

	// Create config endpoint
	config.HandleFunc(fmt.Sprintf("/config/%s/services/%s", service.Namespace, service.Id), config.HandleServiceEndpoint, []model.Scope{model.Read, model.Delete})
	config.serveMux.HandleFunc(fmt.Sprintf("/config/%s/services/%s/status", service.Namespace, service.Id), config.HandleServiceStatusEndpoint)

	// Return service information to the client
	w.Header().Set("Content-Type", "application/json")

	responseBytes, err := json.Marshal(service)
	if err != nil {
		logrus.WithError(err).Error("Failed to marshal service response")
		http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	_, err = w.Write(responseBytes)
	if err != nil {
		logrus.WithError(err).Error("Error writing create service response")
		return
	}
}

// HandleServiceEndpoint handles requests to the /config/<namespace>/services/<id> endpoint
func (config *UserConfigData) HandleServiceEndpoint(w http.ResponseWriter, r *http.Request) {
	// Parse service ID from the URL
	parts := strings.Split(r.URL.Path, "/")
	id := parts[4]

	config.servicesMu.RLock()
	service, ok := config.services[id]
	config.servicesMu.RUnlock()
	if !ok {
		http.Error(w, "Service not found", http.StatusNotFound)
		return
	}

	switch r.Method {
	case "HEAD":
		config.headService(w, r, service)
	case "GET":
		config.getService(w, r, service)
	case "DELETE":
		config.deleteService(w, r, service)
	default:
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

// generateServiceETag generates a consistent ETag based on the marshaled service data
func generateServiceETag(marshaledData []byte) string {
	hash := sha256.Sum256(marshaledData)
	return hex.EncodeToString(hash[:8]) // Use first 8 bytes for a shorter ETag
}

// headService HEAD config/services/<namespace>/<id> returns the ETag header for the service with the given ID
func (config *UserConfigData) headService(w http.ResponseWriter, _ *http.Request, service *model.Service) {
	logrus.WithFields(logrus.Fields{"service_id": service.Id}).Debug("Request HEAD for service")

	marshaledData, err := json.Marshal(&service)
	if err != nil {
		logrus.WithError(err).Error("Failed to marshal service for HEAD request")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	header := w.Header()
	header.Set("Content-Type", "application/json")
	header.Set("ETag", generateServiceETag(marshaledData))
	w.WriteHeader(http.StatusOK)
}

// getService GET config/services/<namespace>/<id> returns the full service JSON with ETag
func (config *UserConfigData) getService(w http.ResponseWriter, _ *http.Request, service *model.Service) {
	logrus.WithFields(logrus.Fields{"service_id": service.Id}).Info("Request GET for service")

	marshaledData, err := json.Marshal(&service)
	if err != nil {
		logrus.WithError(err).Error("Failed to marshal service for GET request")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	header := w.Header()
	header.Set("Content-Type", "application/json")
	header.Set("ETag", generateServiceETag(marshaledData))

	_, err = w.Write(marshaledData)
	if err != nil {
		logrus.WithError(err).Error("Error writing service response body")
	}
}

// DELETE config deletes a service with the given ID
func (config *UserConfigData) deleteService(w http.ResponseWriter, _ *http.Request, service *model.Service) {
	logrus.WithFields(logrus.Fields{"service_id": service.Id}).Info("Request to delete service")

	service.Stop()
	config.servicesMu.Lock()
	delete(config.services, service.Id)
	config.servicesMu.Unlock()

	config.etagServices++
	w.WriteHeader(http.StatusOK)
}

func (config *UserConfigData) HandleServiceStatusEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 6 || parts[5] != "status" {
		http.Error(w, "Invalid status endpoint", http.StatusBadRequest)
		return
	}
	id := parts[4]

	var payload struct {
		Status     string `json:"status"`
		StatusText string `json:"status_text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(payload.Status) == "" {
		http.Error(w, "status is required", http.StatusBadRequest)
		return
	}

	config.servicesMu.Lock()
	service, ok := config.services[id]
	if ok && service != nil {
		service.StatusValue = payload.Status
		service.StatusText = payload.StatusText
		service.StatusUpdated = time.Now()
	}
	config.servicesMu.Unlock()

	if !ok {
		http.Error(w, "Service not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
