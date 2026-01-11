package services

import (
	"aggregator/auth"
	"aggregator/model"
	"context"
	"fmt"
	"strings"
	"time"

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

func CreateService(request model.ServiceRequest) (*model.Service, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	useUMA := strings.TrimSpace(request.Owner.AuthzServerURL) != ""
	service := model.Service{
		Id:            request.Id,
		Description:   request.Description,
		Namespace:     request.Owner.Namespace,
		PubEndpoints:  []string{},
		PrivEndpoints: []string{},
		Deployments:   []appsv1.Deployment{},
		Services:      []corev1.Service{},
		Ingresses:     []networkingv1.Ingress{},
	}

	// Clean up if anything fails
	cleanup := func() {
		if err := service.Stop(); err != nil {
			logrus.WithError(err).Warn("Failed to clean up service resources")
		}
	}

	// Create Deployment
	if err := createDeployment(&service, 1, useUMA, ctx); err != nil {
		cleanup()
		return nil, fmt.Errorf("pod creation failed: %w", err)
	}

	// Create Service
	if err := createServiceResource(&service, ctx); err != nil {
		cleanup()
		return nil, fmt.Errorf("service creation failed: %w", err)
	}

	// Create Ingress
	if err := createIngressRoute(&service, request.Owner, ctx); err != nil {
		cleanup()
		return nil, fmt.Errorf("ingress route creation failed: %w", err)
	}

	// return fully created service
	return &service, nil
}

func createDeployment(service *model.Service, replicas int32, useUMA bool, ctx context.Context) error {
	labels := map[string]string{
		"app":       service.Id,
		"namespace": service.Namespace,
	}

	container := corev1.Container{
		Name:            service.Id,
		Image:           service.Id,
		ImagePullPolicy: corev1.PullNever,
		Env: []corev1.EnvVar{
			{Name: "QUERY", Value: `
				PREFIX ex: <http://example.org/>
				SELECT ?value ?unit
				WHERE {
					?obs ex:value ?value ;
							ex:unit  ?unit .
				}`,
			},
			{Name: "SOURCE", Value: "https://pacsoi-kvasir.faqir.org/patient0/slices/AggregatorDemoSlice/query"},
			{Name: "SCHEMA", Value: `type Query {
					observations: [ex_Observation]!
					observation(id: ID!): ex_Observation
				}

				type ex_Observation {
					id: ID!
					ex_value: Int!
					ex_unit: String!
					ex_timestamp: DateTime!
				}

				type Mutation {
					add(obs: [ObservationInput!]!): ID!
				}

				type Subscription {
					observationAdded: ex_Observation!
				}
					
				input ObservationInput @class(iri: "ex:Observation") {
					id: ID!
					ex_value: Int!
					ex_unit: String!
					ex_timestamp: DateTime!
				}`,
			},
			{Name: "CONTEXT", Value: `{
  				"kss": "https://kvasir.discover.ilabt.imec.be/vocab#",
  				"schema": "http://schema.org/",
  				"ex": "http://example.org/"
				}`,
			},
			{Name: "LOG_LEVEL", Value: model.LogLevel.String()},
		},
		Ports: []corev1.ContainerPort{
			{ContainerPort: 8080},
		},
	}

	if useUMA {
		container.Env = append(container.Env,
			corev1.EnvVar{Name: "HTTP_PROXY", Value: fmt.Sprintf("http://egress-uma.%s.svc.cluster.local:8080", service.Namespace)},
			corev1.EnvVar{Name: "http_proxy", Value: fmt.Sprintf("http://egress-uma.%s.svc.cluster.local:8080", service.Namespace)},
		)
	}

	deploySpec := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      service.Id,
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
		return fmt.Errorf("failed to create deployment %s: %w", service.Id, err)
	}
	service.Deployments = append(service.Deployments, *deploy)

	logrus.Infof("Deployment %s created successfully in namespace %s", service.Id, service.Namespace)
	return nil
}

func createServiceResource(service *model.Service, ctx context.Context) error {
	svcName := service.Id + "-service"

	// Check if service already exists
	_, err := model.Clientset.CoreV1().Services(service.Namespace).Get(ctx, svcName, metav1.GetOptions{})
	if err == nil {
		return fmt.Errorf("service %s already exists in namespace %s", svcName, service.Namespace)
	}

	// Specify Service
	svcSpec := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: svcName,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Selector: map[string]string{
				"app":       service.Id,
				"namespace": service.Namespace,
			},
			Ports: []corev1.ServicePort{
				{
					Port:       8080,
					TargetPort: intstr.FromInt(8080),
				},
			},
		},
	}

	// Create Service
	svc, err := model.Clientset.CoreV1().Services(service.Namespace).Create(ctx, svcSpec, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create service in namespace %s: %w", service.Namespace, err)
	}
	service.Services = append(service.Services, *svc)

	// Register endpoint
	service.PrivEndpoints = append(service.PrivEndpoints, fmt.Sprintf("http://%s.%s.svc.cluster.local:8080", svcName, service.Namespace))

	return nil
}

func createIngressRoute(service *model.Service, owner model.User, ctx context.Context) error {
	irName := service.Namespace + "-" + service.Id + "-ingressroute"
	svcName := service.Id + "-service"
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

	// Create Rewrite Middleware
	// rewriteMiddleware, err := createRewriteMiddleware(service, ctx)
	//if err != nil {
	//	return fmt.Errorf("failed to create rewrite middleware: %w", err)
	//}

	useUMA := strings.TrimSpace(owner.AuthzServerURL) != ""
	middlewares := []interface{}{
		map[string]interface{}{
			"name":      "replace-path",
			"namespace": "aggregator-app",
		},
	}
	if useUMA {
		middlewares = append([]interface{}{
			map[string]interface{}{
				"name":      "ingress-uma",
				"namespace": "aggregator-app",
			},
		}, middlewares...)
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
				"routes": []interface{}{
					map[string]interface{}{
						"match": "Host(`" + model.ExternalHost + "`) && PathPrefix(`/services/" + namespace + "/" + service.Id + "`)",
						"kind":  "Rule",
						"services": []interface{}{
							map[string]interface{}{
								"name":      svcName,
								"namespace": namespace,
								"port":      8080,
							},
						},
						"middlewares": middlewares,
					},
				},
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

	// Register resource & endpoint with policies
	resourceID := fmt.Sprintf("http://%s/services/%s/%s", model.ExternalHost, namespace, service.Id)
	if err := auth.RegisterResource(resourceID, owner.AuthzServerURL, []model.Scope{model.Read}); err != nil {
		return fmt.Errorf("failed to register resource for IngressRoute %q: %w", irName, err)
	}
	if err := auth.DefinePolicy(resourceID, owner.UserId, owner.AuthzServerURL, []model.Scope{model.Read}); err != nil {
		return fmt.Errorf("failed to create policy for IngressRoute %q: %w", irName, err)
	}
	service.PubEndpoints = append(service.PubEndpoints, resourceID)

	logrus.Infof("IngressRoute %s created successfully in namespace %s", irName, "aggregator-app")
	return nil
}

// createRewriteMiddleware creates a Traefik IngressRoute Middleware to rewrite paths.
func createRewriteMiddleware(service *model.Service, ctx context.Context) (string, error) {
	// Use aggregator-app namespace for middlewares
	namespace := "aggregator-app"
	// Middleware name based on path
	prefix := fmt.Sprintf("/services/%s/%s", service.Namespace, service.Id)
	mwName := fmt.Sprintf("rewrite-%s-%s", service.Namespace, service.Id)

	// Traefik Middleware GVR
	middlewareGVR := schema.GroupVersionResource{
		Group:    "traefik.io",
		Version:  "v1alpha1",
		Resource: "middlewares",
	}

	// Check if middleware exists
	_, err := model.DynamicClient.
		Resource(middlewareGVR).
		Namespace(namespace).
		Get(ctx, mwName, metav1.GetOptions{})

	if err == nil {
		// Already exists → reuse
		return mwName, nil
	}
	if !errors.IsNotFound(err) {
		return "", fmt.Errorf("failed to check existing middleware %s: %w", mwName, err)
	}

	// Create new middleware
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "traefik.io/v1alpha1",
			"kind":       "Middleware",
			"metadata": map[string]interface{}{
				"name":      mwName,
				"namespace": namespace,
			},
			"spec": map[string]interface{}{
				"replacePathRegex": map[string]interface{}{
					"regex":       "^" + prefix + "(/.*|$)",
					"replacement": "/$1",
				},
			},
		},
	}

	_, err = model.DynamicClient.
		Resource(middlewareGVR).
		Namespace(namespace).
		Create(ctx, obj, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to create middleware %s: %w", mwName, err)
	}

	return mwName, nil
}
