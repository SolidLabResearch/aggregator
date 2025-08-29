package main

import (
	"aggregator/auth"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const resourceSubscriptionPort = "4449"

// ResourceRegistration represents the data sent by pods to register their endpoints
type ResourceRegistration struct {
	PodName     string   `json:"pod_name"`
	PodIP       string   `json:"pod_ip"`
	Port        int      `json:"port"`
	Endpoint    string   `json:"endpoint"`
	Scopes      []string `json:"scopes"`
	Description string   `json:"description"`
}

var registeredResources = make(map[string]*ResourceRegistration)

func SetupResourceRegistration() {
	// Create the aggregator service for the main server
	if err := createAggregatorService(); err != nil {
		log.Printf("❌ Failed to create aggregator service: %v", err)
	}

	// Create a separate mux for the registration server
	registrationMux := http.NewServeMux()
	registrationMux.HandleFunc("/register", handleResourceRegistration)

	log.Printf("🚀 Resource Registration server starting on port %s", resourceSubscriptionPort)
	log.Printf("🔗 Registration endpoint: http://aggregator-registration:%s/register", resourceSubscriptionPort)

	// Start the registration server with its own mux
	go func() {
		server := &http.Server{
			Addr:    "0.0.0.0:" + resourceSubscriptionPort,
			Handler: registrationMux,
		}
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("Failed to start resource registration server: %v", err)
		}
	}()
}

func handleResourceRegistration(w http.ResponseWriter, r *http.Request) {
	log.Printf("📥 Received resource registration request from %s", r.RemoteAddr)

	if r.Method != "POST" {
		log.Printf("❌ Invalid method %s for resource registration", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var registration ResourceRegistration
	if err := json.NewDecoder(r.Body).Decode(&registration); err != nil {
		log.Printf("❌ Failed to decode registration JSON: %v", err)
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	// Extract actorID from pod_name
	actorID := registration.PodName
	if actorID == "" {
		log.Printf("❌ Missing pod_name in registration")
		http.Error(w, "Missing required field: pod_name", http.StatusBadRequest)
		return
	}

	log.Printf("📋 Processing registration for pod: %s", actorID)
	log.Printf("   Pod IP: %s", registration.PodIP)
	log.Printf("   Port: %d", registration.Port)
	log.Printf("   Endpoint: %s", registration.Endpoint)
	log.Printf("   Scopes: %v", registration.Scopes)

	// Default endpoint to "/" if not specified
	if registration.Endpoint == "" {
		registration.Endpoint = "/"
	}

	// Validate required fields
	if registration.PodIP == "" || registration.Port == 0 {
		log.Printf("❌ Missing required fields in registration")
		http.Error(w, "Missing required fields: pod_ip, port", http.StatusBadRequest)
		return
	}

	if len(registration.Scopes) == 0 {
		log.Printf("❌ No scopes provided for resource %s", actorID)
		http.Error(w, "Scopes are required", http.StatusBadRequest)
		return
	}

	// Store the registration
	resourceKey := fmt.Sprintf("%s%s", actorID, registration.Endpoint)
	registeredResources[resourceKey] = &registration

	// Create Kubernetes service for the pod
	if err := setupServiceForResource(actorID, &registration); err != nil {
		log.Printf("❌ Failed to setup service: %v", err)
		// Continue anyway
	}

	// Register resource with UMA Authorization Server
	if err := registerResourceWithUMA(actorID, &registration); err != nil {
		log.Printf("❌ Failed to register resource with UMA: %v", err)
		// Continue anyway - the service is still functional
	}

	log.Printf("🎉 Successfully registered resource: %s from pod %s", registration.Endpoint, actorID)

	response := map[string]interface{}{
		"status":       "success",
		"message":      "Resource registered successfully",
		"external_url": fmt.Sprintf("%s://%s:%s/%s%s", Protocol, Host, ServerPort, actorID, registration.Endpoint),
		"actor_id":     actorID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func setupServiceForResource(actorID string, registration *ResourceRegistration) error {
	log.Printf("��� Creating Kubernetes service for actor %s", actorID)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serviceName := fmt.Sprintf("id%s-service", actorID)

	// Check if service already exists
	_, err := Clientset.CoreV1().Services("default").Get(ctx, serviceName, metav1.GetOptions{})
	if err == nil {
		log.Printf("✅ Service %s already exists", serviceName)
		return nil
	}

	// Create new service
	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: serviceName,
			Labels: map[string]string{
				"app":       actorID,
				"component": "actor-service",
			},
		},
		Spec: v1.ServiceSpec{
			Selector: map[string]string{
				"app": actorID,
			},
			Ports: []v1.ServicePort{
				{
					Name:       "http",
					Port:       80,
					TargetPort: intstr.FromInt(registration.Port),
					Protocol:   v1.ProtocolTCP,
				},
			},
			Type: v1.ServiceTypeClusterIP,
		},
	}

	_, err = Clientset.CoreV1().Services("default").Create(ctx, service, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create service %s: %v", serviceName, err)
	}

	log.Printf("✅ Created Kubernetes service %s for actor %s", serviceName, actorID)
	return nil
}

func registerResourceWithUMA(actorID string, registration *ResourceRegistration) error {
	log.Printf("🔑 Registering resource with UMA for actor %s", actorID)

	// Convert string scopes to auth.ResourceScope types
	resourceScopes := make([]auth.ResourceScope, 0, len(registration.Scopes))
	for _, scope := range registration.Scopes {
		switch strings.ToLower(scope) {
		case "read":
			resourceScopes = append(resourceScopes, auth.ScopeRead)
		case "write":
			resourceScopes = append(resourceScopes, auth.ScopeWrite)
		case "append":
			resourceScopes = append(resourceScopes, auth.ScopeAppend)
		case "create":
			resourceScopes = append(resourceScopes, auth.ScopeCreate)
		case "delete":
			resourceScopes = append(resourceScopes, auth.ScopeDelete)
		default:
			log.Printf("⚠️ Unknown scope '%s' for resource %s, skipping", scope, actorID)
		}
	}

	if len(resourceScopes) == 0 {
		return fmt.Errorf("no valid UMA scopes found for resource %s", actorID)
	}

	// Create the resource ID - this should match the external URL pattern
	resourceID := fmt.Sprintf("%s://%s:%s/%s%s", Protocol, Host, ServerPort, actorID, registration.Endpoint)

	// Register the resource with UMA
	if err := auth.CreateResource(resourceID, resourceScopes); err != nil {
		return fmt.Errorf("failed to create UMA resource: %v", err)
	}

	log.Printf("✅ Successfully registered resource with UMA for actor %s with scopes %v", actorID, resourceScopes)
	return nil
}

// getHostIPForCluster gets the host IP address that's accessible from inside the cluster
func getHostIPForCluster() (string, error) {
	// For minikube, pods can reach the host via the gateway IP
	// For minikube, we need to get the host IP that's accessible from pods
	// This is typically the minikube VM's host-only adapter IP

	// Try to get the IP by connecting to a known external service
	// This will give us the local IP that would be used for outbound connections
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", fmt.Errorf("failed to get local IP: %v", err)
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	hostIP := localAddr.IP.String()

	log.Printf("🔍 Detected host IP accessible from cluster: %s", hostIP)
	return hostIP, nil
}

func createAggregatorService() error {
	log.Printf("🔧 Creating aggregator service for resource registration")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get the actual host IP address dynamically
	hostIP, err := getHostIPForCluster()
	if err != nil {
		return err
	}

	// Create service and endpoint for the resource registration
	registrationService := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: "aggregator-registration",
			Labels: map[string]string{
				"app":       "aggregator",
				"component": "registration-service",
			},
		},
		Spec: v1.ServiceSpec{
			Ports: []v1.ServicePort{
				{
					Name:       "registration",
					Port:       4449,
					TargetPort: intstr.FromInt(4449),
					Protocol:   v1.ProtocolTCP,
				},
			},
			Type: v1.ServiceTypeClusterIP,
		},
	}

	// Create endpoint that points to the host
	registrationEndpoint := &v1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name: "aggregator-registration",
		},
		Subsets: []v1.EndpointSubset{
			{
				Addresses: []v1.EndpointAddress{
					{
						IP: hostIP,
					},
				},
				Ports: []v1.EndpointPort{
					{
						Port:     4449,
						Protocol: v1.ProtocolTCP,
					},
				},
			},
		},
	}

	// Check if registration service already exists
	_, err = Clientset.CoreV1().Services("default").Get(ctx, "aggregator-registration", metav1.GetOptions{})
	if err == nil {
		log.Printf("✅ Service aggregator-registration already exists")
		// Update the endpoint to make sure it points to the host
		_, err = Clientset.CoreV1().Endpoints("default").Update(ctx, registrationEndpoint, metav1.UpdateOptions{})
		if err != nil {
			log.Printf("❌ Failed to update registration endpoint: %v", err)
		} else {
			log.Printf("✅ Updated aggregator-registration endpoint to point to host")
		}
	} else {
		// Create the registration service
		_, err = Clientset.CoreV1().Services("default").Create(ctx, registrationService, metav1.CreateOptions{})
		if err != nil {
			log.Printf("❌ Failed to create registration service: %v", err)
		} else {
			log.Printf("✅ Created aggregator-registration service")
		}

		// Create the endpoint
		_, err = Clientset.CoreV1().Endpoints("default").Create(ctx, registrationEndpoint, metav1.CreateOptions{})
		if err != nil {
			log.Printf("❌ Failed to create registration endpoint: %v", err)
		} else {
			log.Printf("✅ Created aggregator-registration endpoint pointing to host")
		}
	}

	// Create service for the main aggregator (if it doesn't exist)
	mainService := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: "aggregator-service",
			Labels: map[string]string{
				"app":       "aggregator",
				"component": "main-service",
			},
		},
		Spec: v1.ServiceSpec{
			Ports: []v1.ServicePort{
				{
					Name:       "http",
					Port:       80,
					TargetPort: intstr.FromInt(5000),
					Protocol:   v1.ProtocolTCP,
				},
			},
			Type: v1.ServiceTypeClusterIP,
		},
	}

	// Create endpoint for main service that points to the host
	mainEndpoint := &v1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name: "aggregator-service",
		},
		Subsets: []v1.EndpointSubset{
			{
				Addresses: []v1.EndpointAddress{
					{
						IP: hostIP,
					},
				},
				Ports: []v1.EndpointPort{
					{
						Port:     5000,
						Protocol: v1.ProtocolTCP,
					},
				},
			},
		},
	}

	// Check if main service already exists
	_, err = Clientset.CoreV1().Services("default").Get(ctx, "aggregator-service", metav1.GetOptions{})
	if err == nil {
		log.Printf("✅ Service aggregator-service already exists")
		// Update the endpoint to make sure it points to the host
		_, err = Clientset.CoreV1().Endpoints("default").Update(ctx, mainEndpoint, metav1.UpdateOptions{})
		if err != nil {
			log.Printf("❌ Failed to update main service endpoint: %v", err)
		} else {
			log.Printf("✅ Updated aggregator-service endpoint to point to host")
		}
	} else {
		// Create the main service
		_, err = Clientset.CoreV1().Services("default").Create(ctx, mainService, metav1.CreateOptions{})
		if err != nil {
			log.Printf("❌ Failed to create main aggregator service: %v", err)
		} else {
			log.Printf("✅ Created aggregator-service")
		}

		// Create the endpoint
		_, err = Clientset.CoreV1().Endpoints("default").Create(ctx, mainEndpoint, metav1.CreateOptions{})
		if err != nil {
			log.Printf("❌ Failed to create main service endpoint: %v", err)
		} else {
			log.Printf("✅ Created aggregator-service endpoint pointing to host")
		}
	}

	return nil
}
