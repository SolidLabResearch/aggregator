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

// extractQueryAndSources parses the FnO execution description and extracts query and sources
func extractQueryAndSources(description string) (query string, sources []string, err error) {
	// Parse RDF using rdfgo
	quadStream, errChan := rdfgo.Parse(
		strings.NewReader(description),
		rdfgo.ParserOptions{
			Format: "text/turtle",
		},
	)

	// Create RDF store
	store := rdfgo.NewStore()

	// Handle parsing errors
	go func() {
		for parseErr := range errChan {
			if parseErr != nil {
				logrus.WithError(parseErr).Warn("Error parsing FnO description")
			}
		}
	}()

	// Import quads into store
	store.Import(quadStream)

	// Find the config namespace by looking for any predicate that ends with queryString or sources
	var configNamespace string
	allQuads := rdfgo.Stream(store.Match(nil, nil, nil, nil)).ToArray()
	for _, quad := range allQuads {
		predicateValue := quad.GetPredicate().GetValue()
		if strings.HasSuffix(predicateValue, "queryString") {
			configNamespace = strings.TrimSuffix(predicateValue, "queryString")
			break
		}
		if strings.HasSuffix(predicateValue, "sources") {
			configNamespace = strings.TrimSuffix(predicateValue, "sources")
			break
		}
	}

	if configNamespace == "" {
		return "", nil, fmt.Errorf("could not determine config namespace from FnO description")
	}

	logrus.Debugf("Detected config namespace: %s", configNamespace)

	// Define predicates using detected namespace
	queryStringPredicate := rdfgo.NewNamedNode(configNamespace + "queryString")
	sourcesPredicate := rdfgo.NewNamedNode(configNamespace + "sources")
	rdfFirst := rdfgo.NewNamedNode("http://www.w3.org/1999/02/22-rdf-syntax-ns#first")
	rdfRest := rdfgo.NewNamedNode("http://www.w3.org/1999/02/22-rdf-syntax-ns#rest")
	rdfNil := rdfgo.NewNamedNode("http://www.w3.org/1999/02/22-rdf-syntax-ns#nil")

	// Extract queryString
	queryMatches := rdfgo.Stream(store.Match(nil, queryStringPredicate, nil, nil)).ToArray()
	if len(queryMatches) > 0 {
		query = queryMatches[0].GetObject().GetValue()
	}

	// Extract sources (RDF list)
	sourcesMatches := rdfgo.Stream(store.Match(nil, sourcesPredicate, nil, nil)).ToArray()
	if len(sourcesMatches) > 0 {
		listNode := sourcesMatches[0].GetObject()

		// Traverse RDF list
		for {
			if listNode.GetValue() == rdfNil.GetValue() {
				break
			}

			// Get rdf:first (the current item)
			firstMatches := rdfgo.Stream(store.Match(listNode, rdfFirst, nil, nil)).ToArray()
			if len(firstMatches) > 0 {
				sources = append(sources, firstMatches[0].GetObject().GetValue())
			}

			// Get rdf:rest (the next node in the list)
			restMatches := rdfgo.Stream(store.Match(listNode, rdfRest, nil, nil)).ToArray()
			if len(restMatches) == 0 {
				break
			}
			listNode = restMatches[0].GetObject()
		}
	}

	if query == "" {
		return "", nil, fmt.Errorf("could not extract queryString from FnO description")
	}
	if len(sources) == 0 {
		return "", nil, fmt.Errorf("could not extract sources from FnO description")
	}

	return query, sources, nil
}

func CreateService(request model.ServiceRequest) (*model.Service, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if request.Description == "" {
		return nil, fmt.Errorf("either query/sources or FnO description must be provided")
	}

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
		CreatedAt:     time.Now(),
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

	query, sources, err := extractQueryAndSources(service.Description)
	if err != nil {
		return fmt.Errorf("failed to extract query and sources from FnO description: %w", err)
	}

	container := corev1.Container{
		Name:            service.Id,
		Image:           "comunica", // Use a valid image for testing
		ImagePullPolicy: corev1.PullNever,
		Env: []corev1.EnvVar{
			{Name: "QUERY", Value: query},
			{Name: "SOURCES", Value: strings.Join(sources, ",")},
			/*
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
			*/
			{Name: "LOG_LEVEL", Value: model.LogLevel.String()},
		},
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
	svcName := "svc-" + service.Id

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
	svcName := "svc-" + service.Id
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
