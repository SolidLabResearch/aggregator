package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"aggregator/actors"
	"aggregator/auth"
	"aggregator/model"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type UserConfigData struct {
	owner               model.User
	etagActors          int
	etagTransformations int
	actors              map[string]model.Actor
	serveMux            *http.ServeMux
}

func InitUserConfiguration(mux *http.ServeMux, user model.User) error {
	config := UserConfigData{
		owner:               user,
		etagActors:          0,
		etagTransformations: 0,
		actors:              make(map[string]model.Actor),
		serveMux:            mux,
	}

	pattern := fmt.Sprintf("/config/%s/actors", user.Namespace)
	if err := config.HandleFunc(pattern, config.HandleActorsEndpoint, []model.Scope{model.Read, model.Create}); err != nil {
		logrus.WithError(err).Errorf("Failed to initialize user configuration endpoint '%s'", pattern)
		return fmt.Errorf("initUserConfiguration: failed to register handler for %s: %w", pattern, err)
	}

	logrus.Infof("User configuration endpoint initialized for user %s at %s", user.UserId, pattern)
	return nil
}

func (config *UserConfigData) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request), scopes []model.Scope) error {
	fullURL := fmt.Sprintf("%s://%s%s", model.Protocol, model.ExternalHost, pattern)
	logrus.Debugf("Registering handler for pattern '%s' at URL '%s'", pattern, fullURL)

	// Register HTTP handler
	config.serveMux.HandleFunc(pattern, handler)
	logrus.Infof("Handler registered for pattern: %s", pattern)

	// Register the resource with the Authorization Server
	if err := auth.RegisterResource(fullURL, model.AggregatorASURL, scopes); err != nil {
		logrus.WithError(err).Errorf("Failed to register resource for URL '%s'", fullURL)
		return fmt.Errorf("HandleFunc: registerResource failed for %s: %w", fullURL, err)
	}
	logrus.Debugf("Resource registered successfully for URL '%s'", fullURL)

	// Define policy for the resource
	if err := auth.DefinePolicy(fullURL, config.owner.UserId, model.AggregatorASURL, scopes); err != nil {
		logrus.WithError(err).Errorf("Failed to define policy for URL '%s' and user '%s'", fullURL, config.owner.UserId)
		return fmt.Errorf("HandleFunc: definePolicy failed for %s: %w", fullURL, err)
	}
	logrus.Debugf("Policy defined successfully for URL '%s' and user '%s'", fullURL, config.owner.UserId)

	logrus.Info("HandleFunc setup completed for pattern: ", pattern)
	return nil
}

// HandleActorsEndpoint handles requests to the /config/<namespace>/actors endpoint
func (config *UserConfigData) HandleActorsEndpoint(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "HEAD":
		config.headActors(w, r)
	case "GET":
		config.getActors(w, r)
	case "POST":
		config.postActor(w, r)
	default:
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
}

func (config *UserConfigData) headActors(w http.ResponseWriter, _ *http.Request) {
	header := w.Header()
	header.Set("Content-Type", "application/json")
	header.Set("ETag", strconv.Itoa(config.etagActors))
	w.WriteHeader(http.StatusOK)
}

func (config *UserConfigData) getActors(w http.ResponseWriter, _ *http.Request) {
	actorList := []model.Actor{}
	for _, actor := range config.actors {
		actorList = append(actorList, actor)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", strconv.Itoa(config.etagActors))
	err := json.NewEncoder(w).Encode(actorList)
	if err != nil {
		logrus.WithError(err).Error("Failed to encode actor list")
		http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
		return
	}
}

func (config *UserConfigData) postActor(w http.ResponseWriter, r *http.Request) {
	logrus.Info("Recieved request to register a actor")
	// read request body
	var request model.ActorRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// add request metadata
	request.Owner = config.owner
	if request.Id == "" {
		request.Id = uuid.NewString()
	}

	if _, exists := config.actors[request.Id]; exists {
		http.Error(w, "Actor id already registered for user", http.StatusConflict)
		return
	}

	// create actor
	actor, err := actors.CreateActor(request)
	if err != nil {
		logrus.WithError(err).Error("Failed to create actor")
		http.Error(w, fmt.Sprintf("Failed to create actor: %v", err), http.StatusInternalServerError)
		return
	}

	// Store actor
	config.actors[request.Id] = *actor
	config.etagActors++

	// Create config and status endpoints
	config.HandleFunc(fmt.Sprintf("/config/%s/actors/%s", actor.Namespace, actor.Id), config.HandleActorEndpoint, []model.Scope{model.Read})
	config.HandleFunc(fmt.Sprintf("/config/%s/actors/%s/status", actor.Namespace, actor.Id), config.HandleStatusEndpoint, []model.Scope{model.Read})

	// Return actor information to the client
	w.Header().Set("Content-Type", "application/json")

	responseBytes, err := json.Marshal(actor)
	if err != nil {
		logrus.WithError(err).Error("Failed to marshal actor response")
		http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusAccepted)
	_, err = w.Write(responseBytes)
	if err != nil {
		logrus.WithError(err).Error("Error writing create actor response")
		return
	}
}

func (config *UserConfigData) HandleStatusEndpoint(w http.ResponseWriter, r *http.Request) {
	logrusEntry := logrus.WithFields(logrus.Fields{
		"method": r.Method,
		"path":   r.URL.Path,
	})

	logrusEntry.Debug("Handling status endpoint request")

	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		logrusEntry.Error("Invalid URL format: expected at least 5 parts")
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}

	id := parts[4]
	logrusEntry = logrusEntry.WithField("actor_id", id)

	actor, ok := config.actors[id]
	if !ok {
		logrusEntry.Error("Actor not found")
		http.Error(w, "Actor not found", http.StatusNotFound)
		return
	}

	logrusEntry.Debug("Found actor, checking status")
	ready := actor.Status()

	w.Header().Set("Content-Type", "application/json")

	if ready {
		logrusEntry.Info("Actor ready")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(map[string]bool{"ready": true}); err != nil {
			logrusEntry.Error("Failed to encode JSON response: ", err)
		}
	} else {
		logrusEntry.Warn("Actor not ready")
		w.WriteHeader(http.StatusServiceUnavailable)
		if err := json.NewEncoder(w).Encode(map[string]bool{"ready": false}); err != nil {
			logrusEntry.Error("Failed to encode JSON response: ", err)
		}
	}
}

// HandleActorEndpoint handles requests to the /config/<namespace>/actors/<id> endpoint
func (config *UserConfigData) HandleActorEndpoint(w http.ResponseWriter, r *http.Request) {
	// Parse actor ID from the URL
	parts := strings.Split(r.URL.Path, "/")
	id := parts[4]

	actor, ok := config.actors[id]
	if !ok {
		http.Error(w, "Actor not found", http.StatusNotFound)
		return
	}

	switch r.Method {
	case "HEAD":
		config.headActor(w, r, actor)
	case "GET":
		config.getActor(w, r, actor)
	case "DELETE":
		config.deleteActor(w, r, actor)
	default:
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

// generateActorETag generates a consistent ETag based on the marshaled actor data
func generateActorETag(marshaledData []byte) string {
	hash := sha256.Sum256(marshaledData)
	return hex.EncodeToString(hash[:8]) // Use first 8 bytes for a shorter ETag
}

// headActor HEAD config/actors/<namespace>/<id> returns the ETag header for the actor with the given ID
func (config *UserConfigData) headActor(w http.ResponseWriter, _ *http.Request, actor model.Actor) {
	logrus.WithFields(logrus.Fields{"actor_id": actor.Id}).Debug("Request HEAD for actor")

	marshaledData, err := json.Marshal(&actor)
	if err != nil {
		logrus.WithError(err).Error("Failed to marshal actor for HEAD request")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	header := w.Header()
	header.Set("Content-Type", "application/json")
	header.Set("ETag", generateActorETag(marshaledData))
	w.WriteHeader(http.StatusOK)
}

// getActor GET config/actors/<namespace>/<id> returns the full actor JSON with ETag
func (config *UserConfigData) getActor(w http.ResponseWriter, _ *http.Request, actor model.Actor) {
	logrus.WithFields(logrus.Fields{"actor_id": actor.Id}).Info("Request GET for actor")

	marshaledData, err := json.Marshal(&actor)
	if err != nil {
		logrus.WithError(err).Error("Failed to marshal actor for GET request")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	header := w.Header()
	header.Set("Content-Type", "application/json")
	header.Set("ETag", generateActorETag(marshaledData))

	_, err = w.Write(marshaledData)
	if err != nil {
		logrus.WithError(err).Error("Error writing actor response body")
	}
}

// DELETE config deletes an actor with the given ID
func (config *UserConfigData) deleteActor(w http.ResponseWriter, _ *http.Request, actor model.Actor) {
	logrus.WithFields(logrus.Fields{"actor_id": actor.Id}).Info("Request to delete transformation")

	actor.Stop()
	delete(config.actors, actor.Id)

	config.etagActors++
	w.WriteHeader(http.StatusOK)
}
