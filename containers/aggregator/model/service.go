package model

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
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

func (service *Service) Status() bool {
	logEntry := logrus.WithField("service_id", service.Id)
	logEntry.Debug("Checking service status")

	for _, dep := range service.Deployments {
		logEntry := logEntry.WithField("deployment", dep.Name)
		logEntry.Debugf("Deployment available replicas: %d", dep.Status.AvailableReplicas)
		if dep.Status.AvailableReplicas == 0 {
			logEntry.Warn("Deployment has zero available replicas, service not ready")
			return false
		}
	}

	logEntry.Info("All deployments have available replicas, service ready")
	return true
}

func (service *Service) MarshalJSON() ([]byte, error) {
	type serviceJSON struct {
		ID          string   `json:"id"`
		Description string   `json:"description"`
		Namespace   string   `json:"namespace"`
		Config      string   `json:"config"`
		Status      string   `json:"status"`
		Endpoints   []string `json:"endpoints"`
	}

	out := serviceJSON{
		ID:          service.Id,
		Description: service.Description,
		Namespace:   service.Namespace,
		Config:      fmt.Sprintf("http://%s/config/%s/services/%s", ExternalHost, service.Namespace, service.Id),
		Status:      fmt.Sprintf("http://%s/config/%s/services/%s/status", ExternalHost, service.Namespace, service.Id),
		Endpoints:   service.PubEndpoints,
	}

	return json.Marshal(out)
}
