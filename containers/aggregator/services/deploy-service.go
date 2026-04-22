package services

import (
	"aggregator/model"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func DeployAggregatorService(
	service *model.Service,
) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Convert parameters to environment variables
	envVars, err := ParametersToEnvVars(&service.Application)
	if err != nil {
		logrus.WithError(err).Error("Failed to convert parameters to environment variables")
		return fmt.Errorf("Failed to convert parameters to environment variables")
	}

	useUMA := strings.TrimSpace(model.Owner.AuthzServerURL) != ""

	// Clean up if anything fails
	cleanup := func() {
		if err := service.Stop(); err != nil {
			logrus.WithError(err).Warn("Failed to clean up service resources")
		}
	}

	// Create Deployment
	if err := createDeployment(service, envVars, 1, useUMA, ctx); err != nil {
		cleanup()
		return fmt.Errorf("deployment creation failed: %w", err)
	}

	// Create Service
	if err := createService(service, ctx); err != nil {
		cleanup()
		return fmt.Errorf("service creation failed: %w", err)
	}

	// creation successful
	return nil
}

func createDeployment(
	service *model.Service,
	envVars []corev1.EnvVar,
	replicas int32,
	useUMA bool,
	ctx context.Context,
) error {
	labels := map[string]string{
		"app.kubernetes.io/name":              "aggregator-service",
		"app.kubernetes.io/part-of":           "aggregator-platform",
		"app.kubernetes.io/managed-by":        "aggregator-instance",
		"agg.knows.idlab.ugent.be/managed-by": model.ID,
		"agg.knows.idlab.ugent.be/id":         service.InstanceID,
	}

	if useUMA {
		envVars = append(envVars, []corev1.EnvVar{
			{Name: "HTTP_PROXY", Value: fmt.Sprintf("http://egress-uma-%s.%s.svc.cluster.local:8080", model.ID, model.Namespace)},
			{Name: "http_proxy", Value: fmt.Sprintf("http://egress-uma-%s.%s.svc.cluster.local:8080", model.ID, model.Namespace)},
		}...)
	}

	var containerPorts []corev1.ContainerPort
	for _, port := range service.Application.Transformation.Ports() {
		containerPorts = append(containerPorts, corev1.ContainerPort{ContainerPort: port})
	}

	container := corev1.Container{
		Name:            service.InstanceID,
		Image:           service.Application.Transformation.Image,
		ImagePullPolicy: corev1.PullNever,
		Env:             envVars,
		Ports:           containerPorts,
	}

	deploySpec := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      service.NamespaceID,
			Namespace: model.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app.kubernetes.io/name":              "aggregator-service",
					"agg.knows.idlab.ugent.be/managed-by": model.ID,
					"agg.knows.idlab.ugent.be/id":         service.InstanceID,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: corev1.PodSpec{
					Containers:    []corev1.Container{container},
					RestartPolicy: corev1.RestartPolicyAlways,
				},
			},
		},
	}

	_, err := model.Clientset.AppsV1().Deployments(model.Namespace).Create(ctx, deploySpec, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create deployment %s: %w", service.NamespaceID, err)
	}

	logrus.Infof("Deployment %s created successfully", service.NamespaceID)
	return nil
}

func createService(service *model.Service, ctx context.Context) error {
	// Check if service already exists
	_, err := model.Clientset.CoreV1().Services(model.Namespace).Get(ctx, service.NamespaceID, metav1.GetOptions{})
	if err == nil {
		return fmt.Errorf("service %s already exists", service.NamespaceID)
	}

	// Build service ports
	ports := service.Application.Transformation.Ports()
	servicePorts := make([]corev1.ServicePort, 0, len(ports))
	for _, port := range ports {
		servicePorts = append(servicePorts, corev1.ServicePort{
			Port:       port,
			TargetPort: intstr.FromInt32(port),
		})
	}

	// Specify Service
	svcSpec := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: service.NamespaceID,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Selector: map[string]string{
				"app.kubernetes.io/name":              "aggregator-service",
				"agg.knows.idlab.ugent.be/managed-by": model.ID,
				"agg.knows.idlab.ugent.be/id":         service.InstanceID,
			},
			Ports: servicePorts,
		},
	}

	// Create Service
	_, err = model.Clientset.CoreV1().Services(model.Namespace).Create(ctx, svcSpec, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create service: %w", err)
	}

	return nil
}
