package model

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ServiceRequest struct {
	Id          string `json:"id"`
	Description string `json:"description"`
	Owner       User   `json:"owner"`
}

type Service struct {
	Id            string
	Description   string
	Namespace     string
	PubEndpoints  []string
	PrivEndpoints []string
	Deployments   []appsv1.Deployment
	Services      []corev1.Service
	Ingresses     []networkingv1.Ingress
	CreatedAt     time.Time
}

func (service *Service) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Delete Deployments
	for _, dep := range service.Deployments {
		err := Clientset.AppsV1().Deployments(service.Namespace).Delete(ctx, dep.Name, metav1.DeleteOptions{})
		if err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete deployment %s: %w", dep.Name, err)
		}
	}

	// Delete Services
	for _, svc := range service.Services {
		err := Clientset.CoreV1().Services(service.Namespace).Delete(ctx, svc.Name, metav1.DeleteOptions{})
		if err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete service %s: %w", svc.Name, err)
		}
	}

	// Delete Ingresses
	for _, ing := range service.Ingresses {
		err := Clientset.NetworkingV1().Ingresses(service.Namespace).Delete(ctx, ing.Name, metav1.DeleteOptions{})
		if err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete ingress %s: %w", ing.Name, err)
		}
	}

	return nil
}

func (service *Service) Status() string {
	ctx := context.Background()
	for _, dep := range service.Deployments {
		d, err := Clientset.AppsV1().Deployments(service.Namespace).Get(ctx, dep.Name, metav1.GetOptions{})
		if err != nil {
			return "errored"
		}
		if d.Status.AvailableReplicas == 0 {
			return "starting" // or stopped/starting
		}
	}
	
	// Check if the service endpoint is actually responding
	if len(service.PrivEndpoints) > 0 {
		endpoint := service.PrivEndpoints[0]
		
		// Parse the URL to extract host and port
		u, err := url.Parse(endpoint)
		if err != nil {
			return "starting"
		}
		
		// Try to establish a TCP connection
		conn, err := net.DialTimeout("tcp", u.Host, 200*time.Millisecond)
		if err != nil {
			return "starting"
		}
		defer conn.Close()
	}
	
	return "running"
}

func (service *Service) MarshalJSON() ([]byte, error) {
	type serviceJSON struct {
		ID             string   `json:"id"`
		Status         string   `json:"status"`
		Transformation string   `json:"transformation"`
		CreatedAt      string   `json:"created_at"`
		Location       string   `json:"location"`
	}

	location := ""
	if len(service.PubEndpoints) > 0 {
		location = service.PubEndpoints[0]
	}

	out := serviceJSON{
		ID:             fmt.Sprintf("%s://%s/config/%s/services/%s", Protocol, ExternalHost, service.Namespace, service.Id),
		Status:         service.Status(),
		Transformation: service.Description,
		CreatedAt:      service.CreatedAt.Format(time.RFC3339),
		Location:       location,
	}

	return json.Marshal(out)
}
