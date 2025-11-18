package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type User struct {
	Id        string `json:"id"`
	Secret    string `json:"secret"`
	Issuer    string `json:"issuer"`
	Name      string `json:"name"`
	ASURL     string `json:"as_url"`
	Namespace string `json:"namespace"`
}

var (
	users   = make(map[string]*User)
	userMux sync.Mutex
)

func initUserRegistration(mux *http.ServeMux) {
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		userRegistrationHandler(w, r, mux)
	})
}

func userRegistrationHandler(w http.ResponseWriter, r *http.Request, mux *http.ServeMux) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Decode request JSON into a User
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if user.Id == "" {
		http.Error(w, "Missing required field: id", http.StatusBadRequest)
		return
	}
	if user.Secret == "" {
		http.Error(w, "Missing required field: secret", http.StatusBadRequest)
		return
	}
	if user.Issuer == "" {
		http.Error(w, "Missing required field: issuer", http.StatusBadRequest)
		return
	}
	if user.ASURL == "" {
		http.Error(w, "Missing required field: ASURL", http.StatusBadRequest)
		return
	}

	// Lock for safe concurrent access
	userMux.Lock()
	defer userMux.Unlock()

	// Check if user already exists
	if _, exists := users[user.Id]; exists {
		http.Error(w, "User already registered", http.StatusConflict)
		return
	}

	// Create a unique namespace for the user
	ns, err := createNamespace(user)
	if err != nil {
		logrus.WithError(err).Errorf("Failed to create namespace for %s", user.Id)
		http.Error(w, "Unable to create namespace", http.StatusInternalServerError)
		return
	}
	user.Namespace = ns

	// TODO: also set up egress uma

	// Initiate config endpoint
	initUserConfiguration(mux, user)

	// Store user
	users[user.Id] = &user

	// Respond with the user config endpoint
	response := map[string]interface{}{
		"config": fmt.Sprintf("http://%s/config/%s", ExternalHost, user.Namespace),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

func createNamespace(user User) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	nsName := user.Name
	if nsName == "" {
		nsName = uuid.NewString()
	} else {
		_, err := Clientset.CoreV1().Namespaces().Get(ctx, nsName, metav1.GetOptions{})
		if err == nil {
			nsName = uuid.NewString()
		}
	}

	// Check if namespace already exists
	_, err := Clientset.CoreV1().Namespaces().Get(ctx, nsName, metav1.GetOptions{})
	if err == nil {
		return "", fmt.Errorf("namespace %s already exists", nsName)
	}

	// Create namespace with labels/annotations
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: nsName,
			Labels: map[string]string{
				"created-by": "aggregator",
			},
			Annotations: map[string]string{
				"owner":  user.Id,
				"as_url": user.ASURL,
			},
		},
	}

	_, err = Clientset.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to create namespace %s: %w", nsName, err)
	}

	logrus.Infof("Namespace %s created successfully ✅", nsName)

	return nsName, nil
}
