package types

import (
	"aggregator/vars"
	"context"
	"encoding/json"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ActorRequest struct {
	Id          string `json:"id"`
	Description string `json:"description"`
	Owner       User   `json:"owner"`
}

type Actor struct {
	Id            string
	Description   string
	Namespace     string
	PubEndpoints  []string
	PrivEndpoints []string
	Deployments   []appsv1.Deployment
	Services      []corev1.Service
	Ingresses     []networkingv1.Ingress
}

func (actor *Actor) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Delete Deployments
	for _, dep := range actor.Deployments {
		err := vars.Clientset.AppsV1().Deployments(actor.Namespace).Delete(ctx, dep.Name, metav1.DeleteOptions{})
		if err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete deployment %s: %w", dep.Name, err)
		}
	}

	// Delete Services
	for _, svc := range actor.Services {
		err := vars.Clientset.CoreV1().Services(actor.Namespace).Delete(ctx, svc.Name, metav1.DeleteOptions{})
		if err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete service %s: %w", svc.Name, err)
		}
	}

	// Delete Ingresses
	for _, ing := range actor.Ingresses {
		err := vars.Clientset.NetworkingV1().Ingresses(actor.Namespace).Delete(ctx, ing.Name, metav1.DeleteOptions{})
		if err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete ingress %s: %w", ing.Name, err)
		}
	}

	return nil
}

func (actor *Actor) Status() bool {
	for _, dep := range actor.Deployments {
		if dep.Status.AvailableReplicas == 0 {
			return false
		}
	}
	return true
}

func (actor *Actor) MarshalJSON() ([]byte, error) {
	type actorJSON struct {
		ID          string   `json:"id"`
		Description string   `json:"description"`
		Namespace   string   `json:"namespace"`
		Config      string   `json:"config"`
		Status      string   `json:"status"`
		Endpoints   []string `json:"endpoints"`
	}

	out := actorJSON{
		ID:          actor.Id,
		Description: actor.Description,
		Namespace:   actor.Namespace,
		Config:      fmt.Sprintf("http://%s/config/%s/actors/%s", vars.ExternalHost, actor.Namespace, actor.Id),
		Status:      fmt.Sprintf("http://%s/config/%s/actors/%s/status", vars.ExternalHost, actor.Namespace, actor.Id),
		Endpoints:   actor.PubEndpoints,
	}

	return json.Marshal(out)
}
