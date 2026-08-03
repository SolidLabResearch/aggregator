package model

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Service struct {
	Description    ServiceDescription
	KubernetesName string
	InstanceID     string
	AggPath        string
	FullPath       string
	Deployment     *DeploymentRequest
	Configuration  *ServiceConfiguration
	CreatedAt      time.Time
}

func (service *Service) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Label selector to match the resources
	labelSelector := fmt.Sprintf(
		"app.kubernetes.io/name=aggregator-service,agg.knows.idlab.ugent.be/managed-by=%s,agg.knows.idlab.ugent.be/id=%s",
		ID,
		service.InstanceID,
	)
	// Ensure dependent resources are deleted
	deletePolicy := metav1.DeletePropagationForeground

	// Delete Deployments
	if err := Clientset.AppsV1().Deployments(Namespace).DeleteCollection(ctx, metav1.DeleteOptions{
		PropagationPolicy: &deletePolicy,
	}, metav1.ListOptions{
		LabelSelector: labelSelector,
	}); err != nil {
		return fmt.Errorf("failed to delete deployments: %w", err)
	}

	// Delete Services
	services, err := Clientset.CoreV1().Services(Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return fmt.Errorf("failed to list services: %w", err)
	}

	for _, svc := range services.Items {
		if err := Clientset.CoreV1().Services(Namespace).Delete(ctx, svc.Name, metav1.DeleteOptions{
			PropagationPolicy: &deletePolicy,
		}); err != nil {
			return fmt.Errorf("failed to delete service %s: %w", svc.Name, err)
		}
	}

	return nil
}

func (service *Service) Status() string {
	ctx := context.Background()

	// Label selector to match the resources
	labelSelector := fmt.Sprintf(
		"app.kubernetes.io/name=aggregator-service,agg.knows.idlab.ugent.be/managed-by=%s,agg.knows.idlab.ugent.be/id=%s",
		ID,
		service.InstanceID,
	)

	// Check services and their endpoints
	services, err := Clientset.CoreV1().Services(Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return "errored"
	}
	if len(services.Items) == 0 {
		return "stopped"
	}

	for _, svc := range services.Items {
		endpoints, err := Clientset.CoreV1().Endpoints(Namespace).Get(ctx, svc.Name, metav1.GetOptions{})
		if err != nil {
			return "errored"
		}

		// Check if the service has any ready endpoints
		hasReady := false
		for _, subset := range endpoints.Subsets {
			if len(subset.Addresses) > 0 {
				hasReady = true
				break
			}
		}
		if !hasReady {
			return "starting" // service exists but no pods are ready
		}
	}

	// All deployments have available replicas & services have endpoints
	return "running"
}
