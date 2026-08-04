package model

import (
	"context"
	"errors"
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
	var cleanupErrors []error

	deployments, err := Clientset.AppsV1().Deployments(Namespace).List(ctx, metav1.ListOptions{LabelSelector: labelSelector})
	if err != nil {
		cleanupErrors = append(cleanupErrors, fmt.Errorf("failed to list deployments: %w", err))
	} else {
		for _, deployment := range deployments.Items {
			if err := Clientset.AppsV1().Deployments(Namespace).Delete(ctx, deployment.Name, metav1.DeleteOptions{PropagationPolicy: &deletePolicy}); err != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("failed to delete deployment %s: %w", deployment.Name, err))
			}
		}
	}
	configMaps, err := Clientset.CoreV1().ConfigMaps(Namespace).List(ctx, metav1.ListOptions{LabelSelector: labelSelector})
	if err != nil {
		cleanupErrors = append(cleanupErrors, fmt.Errorf("failed to list config maps: %w", err))
	} else {
		for _, configMap := range configMaps.Items {
			if err := Clientset.CoreV1().ConfigMaps(Namespace).Delete(ctx, configMap.Name, metav1.DeleteOptions{PropagationPolicy: &deletePolicy}); err != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("failed to delete config map %s: %w", configMap.Name, err))
			}
		}
	}
	claims, err := Clientset.CoreV1().PersistentVolumeClaims(Namespace).List(ctx, metav1.ListOptions{LabelSelector: labelSelector})
	if err != nil {
		cleanupErrors = append(cleanupErrors, fmt.Errorf("failed to list persistent volume claims: %w", err))
	} else {
		for _, claim := range claims.Items {
			if err := Clientset.CoreV1().PersistentVolumeClaims(Namespace).Delete(ctx, claim.Name, metav1.DeleteOptions{PropagationPolicy: &deletePolicy}); err != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("failed to delete persistent volume claim %s: %w", claim.Name, err))
			}
		}
	}

	// Delete Services
	services, err := Clientset.CoreV1().Services(Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		cleanupErrors = append(cleanupErrors, fmt.Errorf("failed to list services: %w", err))
	} else {
		for _, svc := range services.Items {
			if err := Clientset.CoreV1().Services(Namespace).Delete(ctx, svc.Name, metav1.DeleteOptions{
				PropagationPolicy: &deletePolicy,
			}); err != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("failed to delete service %s: %w", svc.Name, err))
			}
		}
	}
	return errors.Join(cleanupErrors...)
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
