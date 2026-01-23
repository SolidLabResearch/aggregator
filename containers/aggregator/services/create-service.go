package services

import (
	"aggregator/auth"
	"aggregator/model"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/maartyman/rdfgo"
	"github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
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
		ID:               id,
		Path:             path,
		Exe:              exe,
		Namespace:        model.Namespace,
		ClusterEndpoints: []string{},
		Deployments:      []appsv1.Deployment{},
		Services:         []corev1.Service{},
		Ingresses:        []networkingv1.Ingress{},
		CreatedAt:        time.Now(),
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

	// Create Ingress
	if err := createIngressRoute(&service, exe.Transformation.OutputMapping, model.Owner, ctx); err != nil {
		cleanup()
		return nil, fmt.Errorf("ingress route creation failed: %w", err)
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
		"app":       service.ID,
		"namespace": service.Namespace,
	}

	container := corev1.Container{
		Name:            service.ID,
		Image:           image,
		ImagePullPolicy: corev1.PullNever,
		Env:             envVars,
		Ports: []corev1.ContainerPort{
			{ContainerPort: 8080},
		},
	}

	if useUMA {
		container.Env = append([]corev1.EnvVar{
			{Name: "HTTP_PROXY", Value: fmt.Sprintf("http://egress-uma.%s.svc.cluster.local:8080", service.Namespace)},
			{Name: "http_proxy", Value: fmt.Sprintf("http://egress-uma.%s.svc.cluster.local:8080", service.Namespace)},
		}, container.Env...)
	}

	deploySpec := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      service.ID,
			Namespace: service.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
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

	deploy, err := model.Clientset.AppsV1().Deployments(service.Namespace).Create(ctx, deploySpec, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create deployment %s: %w", service.ID, err)
	}
	service.Deployments = append(service.Deployments, *deploy)

	logrus.Infof("Deployment %s created successfully in namespace %s", service.ID, service.Namespace)
	return nil
}

func createService(service *model.Service, ports []int32, ctx context.Context) error {
	svcName := "svc-" + service.ID

	// Check if service already exists
	_, err := model.Clientset.CoreV1().Services(service.Namespace).Get(ctx, svcName, metav1.GetOptions{})
	if err == nil {
		return fmt.Errorf("service %s already exists in namespace %s", svcName, service.Namespace)
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
			Name: svcName,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Selector: map[string]string{
				"app":       service.ID,
				"namespace": service.Namespace,
			},
			Ports: servicePorts,
		},
	}

	// Create Service
	svc, err := model.Clientset.CoreV1().Services(service.Namespace).Create(ctx, svcSpec, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create service in namespace %s: %w", service.Namespace, err)
	}
	service.Services = append(service.Services, *svc)

	return nil
}

func createIngressRoute(service *model.Service, mappings map[string]model.OutputMapping, owner model.User, ctx context.Context) error {
	irName := service.Namespace + "-" + service.ID + "-ingressroute"
	svcName := "svc-" + service.ID
	namespace := service.Namespace

	// Check if IngressRoute already exists
	ingressRouteGVR := schema.GroupVersionResource{
		Group:    "traefik.io",
		Version:  "v1alpha1",
		Resource: "ingressroutes",
	}

	_, err := model.DynamicClient.
		Resource(ingressRouteGVR).
		Namespace(namespace).
		Get(ctx, irName, metav1.GetOptions{})
	if err == nil {
		return fmt.Errorf("IngressRoute %s already exists in namespace %s", irName, namespace)
	}
	if !errors.IsNotFound(err) {
		return fmt.Errorf("failed to check existing IngressRoute %s: %w", irName, err)
	}

	routes := make([]interface{}, 0, len(mappings))
	for pred, mapping := range mappings {
		// Define replace-path middleware
		mwName := "strip-prefix-" + service.ID + "-" + pred
		middlewareGVR := schema.GroupVersionResource{
			Group:    "traefik.io",
			Version:  "v1alpha1",
			Resource: "middlewares",
		}
		mwObj := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "traefik.io/v1alpha1",
				"kind":       "Middleware",
				"metadata": map[string]interface{}{
					"name":      mwName,
					"namespace": namespace,
				},
				"spec": map[string]interface{}{
					"replacePath": map[string]interface{}{
						"replacement": mapping.Path,
					},
				},
			},
		}
		_, err = model.DynamicClient.Resource(middlewareGVR).Namespace(namespace).Create(ctx, mwObj, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed to create Middleware: %w", err)
		}

		middlewares := []interface{}{
			map[string]interface{}{
				"name":      mwName,
				"namespace": model.Namespace,
			},
		}
		if strings.TrimSpace(owner.AuthzServerURL) != "" {
			middlewares = append([]interface{}{
				map[string]interface{}{
					"name":      "ingress-uma",
					"namespace": "aggregator-app",
				},
			}, middlewares...)
		}

		route := map[string]interface{}{
			"match":    "Host(`" + model.ExternalHost + "`) && PathPrefix(`/" + namespace + service.Path + "/" + pred + "`)",
			"kind":     "Rule",
			"priority": 100,
			"services": []interface{}{
				map[string]interface{}{
					"name":      svcName,
					"namespace": namespace,
					"port":      mapping.Port,
				},
			},
			"middlewares": middlewares,
		}

		routes = append(routes, route)
	}

	// Define IngressRoute spec
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "traefik.io/v1alpha1",
			"kind":       "IngressRoute",
			"metadata": map[string]interface{}{
				"name":      irName,
				"namespace": namespace,
			},
			"spec": map[string]interface{}{
				"entryPoints": []string{"web"},
				"routes":      routes,
			},
		},
	}

	// Create IngressRoute
	_, err = model.DynamicClient.
		Resource(ingressRouteGVR).
		Namespace(namespace).
		Create(ctx, obj, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create IngressRoute %s: %w", irName, err)
	}

	// Register resources & endpoints with policies
	for pred := range mappings {
		outputUri := service.Exe.Transformation.Base + "/" + pred
		resourceId := model.BaseUrl + service.Path + "/" + pred
		if err := auth.RegisterResource(resourceId, owner.AuthzServerURL, []model.Scope{model.Read}); err != nil {
			return fmt.Errorf("failed to register resource for IngressRoute %q: %w", irName, err)
		}
		if err := auth.DefinePolicy(resourceId, owner.UserId, owner.AuthzServerURL, []model.Scope{model.Read}); err != nil {
			return fmt.Errorf("failed to create policy for IngressRoute %q: %w", irName, err)
		}
		service.Exe.Outputs[outputUri] = rdfgo.NewNamedNode(resourceId)
	}

	logrus.Infof("IngressRoute %s created successfully in namespace %s", irName, "aggregator-app")
	return nil
}
