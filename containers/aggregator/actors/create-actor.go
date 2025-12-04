package actors

import (
	"aggregator/auth"
	"aggregator/model"
	"context"
	"crypto/sha1"
	"encoding/hex"
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

func CreateActor(request model.ActorRequest) (*model.Actor, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	actor := model.Actor{
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
		if err := actor.Stop(); err != nil {
			logrus.WithError(err).Warn("Failed to clean up actor resources")
		}
	}

	// Create Deployment
	if err := createDeployment(&actor, 1, ctx); err != nil {
		cleanup()
		return nil, fmt.Errorf("pod creation failed: %w", err)
	}

	// Create Service
	if err := createService(&actor, ctx); err != nil {
		cleanup()
		return nil, fmt.Errorf("service creation failed: %w", err)
	}

	// Create Ingress
	if err := createIngressRoute(&actor, request.Owner, ctx); err != nil {
		cleanup()
		return nil, fmt.Errorf("ingress route creation failed: %w", err)
	}

	// return fully created actor
	return &actor, nil
}

func createDeployment(actor *model.Actor, replicas int32, ctx context.Context) error {
	labels := map[string]string{
		"app":       actor.Id,
		"namespace": actor.Namespace,
	}

	container := corev1.Container{
		Name:            actor.Id,
		Image:           "fetch",
		ImagePullPolicy: corev1.PullNever,
		Env: []corev1.EnvVar{
			{Name: "GET_URL", Value: "http://wsl.local:6000/"},
			{Name: "HTTP_PROXY", Value: fmt.Sprintf("http://egress-uma.%s.svc.cluster.local:8080", actor.Namespace)},
			{Name: "http_proxy", Value: fmt.Sprintf("http://egress-uma.%s.svc.cluster.local:8080", actor.Namespace)},
			{Name: "LOG_LEVEL", Value: model.LogLevel.String()},
		},
		Ports: []corev1.ContainerPort{
			{ContainerPort: 8080},
		},
	}

	deploySpec := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      actor.Id,
			Namespace: actor.Namespace,
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

	deploy, err := model.Clientset.AppsV1().Deployments(actor.Namespace).Create(ctx, deploySpec, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create deployment %s: %w", actor.Id, err)
	}
	actor.Deployments = append(actor.Deployments, *deploy)

	logrus.Infof("Deployment %s created successfully in namespace %s", actor.Id, actor.Namespace)
	return nil
}

func createService(actor *model.Actor, ctx context.Context) error {
	svcName := actor.Id + "-service"

	// Check if service already exists
	_, err := model.Clientset.CoreV1().Services(actor.Namespace).Get(ctx, svcName, metav1.GetOptions{})
	if err == nil {
		return fmt.Errorf("service %s already exists in namespace %s", svcName, actor.Namespace)
	}

	// Specify Service
	svcSpec := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: svcName,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Selector: map[string]string{
				"app":       actor.Id,
				"namespace": actor.Namespace,
			},
			Ports: []corev1.ServicePort{
				{
					Port:       80,
					TargetPort: intstr.FromInt(8080),
				},
			},
		},
	}

	// Create Service
	svc, err := model.Clientset.CoreV1().Services(actor.Namespace).Create(ctx, svcSpec, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create service in namespace %s: %w", actor.Namespace, err)
	}
	actor.Services = append(actor.Services, *svc)

	// Register endpoint
	actor.PrivEndpoints = append(actor.PrivEndpoints, fmt.Sprintf("%s.%s.svc.cluster.local", svcName, actor.Namespace))

	return nil
}

func createIngressRoute(actor *model.Actor, owner model.User, ctx context.Context) error {
	irName := actor.Namespace + "-" + actor.Id + "-ingressroute"
	svcName := actor.Id + "-service"
	namespace := actor.Namespace

	// Check if IngressRoute already exists
	ingressRouteGVR := schema.GroupVersionResource{
		Group:    "traefik.io",
		Version:  "v1alpha1",
		Resource: "ingressroutes",
	}

	_, err := model.DynamicClient.
		Resource(ingressRouteGVR).
		Namespace("aggregator-app").
		Get(ctx, irName, metav1.GetOptions{})
	if err == nil {
		return fmt.Errorf("IngressRoute %s already exists in namespace %s", irName, namespace)
	}
	if !errors.IsNotFound(err) {
		return fmt.Errorf("failed to check existing IngressRoute %s: %w", irName, err)
	}

	// Create Rewrite Middleware
	rewriteMiddleware, err := createRewriteMiddleware("/", ctx)
	if err != nil {
		return fmt.Errorf("failed to create rewrite middleware: %w", err)
	}

	// Define IngressRoute spec
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "traefik.io/v1alpha1",
			"kind":       "IngressRoute",
			"metadata": map[string]interface{}{
				"name":      irName,
				"namespace": "aggregator-app",
			},
			"spec": map[string]interface{}{
				"entryPoints": []string{"web"}, // adjust to websecure if needed
				"routes": []interface{}{
					map[string]interface{}{
						"match": "Host(`" + model.ExternalHost + "`) && PathPrefix(`/actors/" + namespace + "/" + actor.Id + "`)",
						"kind":  "Rule",
						"services": []interface{}{
							map[string]interface{}{
								"name":      svcName,
								"namespace": namespace,
								"port":      80,
							},
						},
						"middlewares": []interface{}{
							map[string]interface{}{
								"name":      "ingress-uma",
								"namespace": "aggregator-app",
							},
							map[string]interface{}{
								"name":      rewriteMiddleware,
								"namespace": "aggregator-app",
							},
						},
					},
				},
			},
		},
	}

	// Create IngressRoute
	_, err = model.DynamicClient.
		Resource(ingressRouteGVR).
		Namespace("aggregator-app").
		Create(ctx, obj, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create IngressRoute %s: %w", irName, err)
	}

	// Register resource & endpoint with policies
	resourceID := fmt.Sprintf("http://%s/actors/%s/%s", model.ExternalHost, namespace, actor.Id)
	if err := auth.RegisterResource(resourceID, owner.AuthzServerURL, []model.Scope{model.Read}); err != nil {
		return fmt.Errorf("failed to register resource for IngressRoute %q: %w", irName, err)
	}
	if err := auth.DefinePolicy(resourceID, owner.UserId, owner.AuthzServerURL, []model.Scope{model.Read}); err != nil {
		return fmt.Errorf("failed to create policy for IngressRoute %q: %w", irName, err)
	}
	actor.PubEndpoints = append(actor.PubEndpoints, resourceID)

	logrus.Infof("IngressRoute %s created successfully in namespace %s", irName, "aggregator-app")
	return nil
}

// createRewriteMiddleware creates a Traefik IngressRoute Middleware to rewrite paths.
func createRewriteMiddleware(path string, ctx context.Context) (string, error) {
	// Use aggregator-app namespace for middlewares
	namespace := "aggregator-app"

	// Sanitize path for name (remove /, replace with -) and hash to avoid collisions / length issues
	cleanPath := strings.ReplaceAll(path, "/", "-")
	if cleanPath == "" {
		cleanPath = "root"
	}
	hash := sha1.Sum([]byte(path))
	mwName := fmt.Sprintf("rewrite-%s%s", cleanPath, hex.EncodeToString(hash[:4])) // short hash for uniqueness

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
				"replacePath": map[string]interface{}{
					"path": path,
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
