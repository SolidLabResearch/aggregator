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

func CreateAggregatorService(
	id string,
	path string,
	exe model.Execution,
) (*model.Service, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Convert parameters to environment variables
	envVars, err := ParametersToEnvVars(exe.Params, exe.Transformation.InputMapping)
	if err != nil {
		logrus.WithError(err).Error("Failed to convert parameters to environment variables")
		return nil, fmt.Errorf("Failed to convert parameters to environment variables")
	}

	useUMA := strings.TrimSpace(model.Owner.AuthzServerURL) != ""
	service := model.Service{
		InstanceID:  id,
		NamespaceID: id + "-" + model.ID,
		Path:        path,
		Exe:         exe,
		CreatedAt:   time.Now(),
	}

	// Clean up if anything fails
	cleanup := func() {
		if err := service.Stop(); err != nil {
			logrus.WithError(err).Warn("Failed to clean up service resources")
		}
	}

	// Create Deployment
	if err := createDeployment(&service, envVars, exe.Transformation.Image, 1, useUMA, ctx); err != nil {
		cleanup()
		return nil, fmt.Errorf("pod creation failed: %w", err)
	}

	// Create Service
	if err := createService(&service, exe.Transformation.Ports(), ctx); err != nil {
		cleanup()
		return nil, fmt.Errorf("service creation failed: %w", err)
	}

	// return fully created service
	return &service, nil
}

func createDeployment(
	service *model.Service,
	envVars []corev1.EnvVar,
	image string,
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

	container := corev1.Container{
		Name:            service.InstanceID,
		Image:           image,
		ImagePullPolicy: corev1.PullNever,
		Env:             envVars,
		Ports: []corev1.ContainerPort{
			{ContainerPort: 8080},
		},
	}

	if useUMA {
		container.Env = append([]corev1.EnvVar{
			{Name: "HTTP_PROXY", Value: fmt.Sprintf("http://egress-uma-%s.%s.svc.cluster.local:8080", model.ID, model.Namespace)},
			{Name: "http_proxy", Value: fmt.Sprintf("http://egress-uma-%s.%s.svc.cluster.local:8080", model.ID, model.Namespace)},
		}, container.Env...)
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

func createService(service *model.Service, ports []int32, ctx context.Context) error {
	// Check if service already exists
	_, err := model.Clientset.CoreV1().Services(model.Namespace).Get(ctx, service.NamespaceID, metav1.GetOptions{})
	if err == nil {
		return fmt.Errorf("service %s already exists", service.NamespaceID)
	}

	// Build service ports
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
