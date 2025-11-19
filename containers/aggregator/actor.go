package main

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
	"k8s.io/apimachinery/pkg/util/intstr"
)

type Actor struct {
	id            string
	description   string
	namespace     string
	pubEndpoints  []string
	privEndpoints []string
	deployments   []appsv1.Deployment
	services      []corev1.Service
	ingresses     []networkingv1.Ingress
}

func createActor(request ActorRequest) (*Actor, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	actor := Actor{
		id:            request.Id,
		description:   request.Description,
		namespace:     request.Owner.Namespace,
		pubEndpoints:  []string{},
		privEndpoints: []string{},
		deployments:   []appsv1.Deployment{},
		services:      []corev1.Service{},
		ingresses:     []networkingv1.Ingress{},
	}

	// Clean up if anything fails
	cleanup := func() {
		if err := actor.Stop(); err != nil {
			logrus.WithError(err).Warn("Failed to clean up actor resources")
		}
	}

	// Create Deployment
	if err := actor.createDeployment(1, ctx); err != nil {
		cleanup()
		return nil, fmt.Errorf("pod creation failed: %w", err)
	}

	// Create Service
	if err := actor.createService(ctx); err != nil {
		cleanup()
		return nil, fmt.Errorf("service creation failed: %w", err)
	}

	// Create Ingress
	if err := actor.createIngress(request.Owner.ASURL, ctx); err != nil {
		cleanup()
		return nil, fmt.Errorf("ingress creation failed: %w", err)
	}

	// return fully created actor
	return &actor, nil
}

func (actor *Actor) createDeployment(replicas int32, ctx context.Context) error {
	labels := map[string]string{
		"app":       actor.id,
		"namespace": actor.namespace,
	}

	container := corev1.Container{
		Name:            actor.id,
		Image:           "echo",
		ImagePullPolicy: corev1.PullNever,
		Env: []corev1.EnvVar{
			{Name: "PIPELINE_DESCRIPTION", Value: actor.description},
			{Name: "SSL_CERT_FILE", Value: "/key-pair/uma-proxy.crt"},
			{Name: "HTTP_PROXY", Value: "http://uma-proxy.uma-proxy-ns.svc.cluster.local:8080"},
			{Name: "HTTPS_PROXY", Value: "http://uma-proxy.uma-proxy-ns.svc.cluster.local:8443"},
			{Name: "LOG_LEVEL", Value: LogLevel.String()},
		},
		Ports: []corev1.ContainerPort{
			{ContainerPort: 8080},
		},
	}

	deploySpec := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      actor.id,
			Namespace: actor.namespace,
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

	deploy, err := Clientset.AppsV1().Deployments(actor.namespace).Create(ctx, deploySpec, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create deployment %s: %w", actor.id, err)
	}
	actor.deployments = append(actor.deployments, *deploy)

	logrus.Infof("Deployment %s created successfully in namespace %s", actor.id, actor.namespace)
	return nil
}

func (actor *Actor) createService(ctx context.Context) error {
	svcName := actor.id + "-service"

	// Check if service already exists
	_, err := Clientset.CoreV1().Services(actor.namespace).Get(ctx, svcName, metav1.GetOptions{})
	if err == nil {
		return fmt.Errorf("service %s already exists in namespace %s", svcName, actor.namespace)
	}

	// Specify Service
	svcSpec := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: svcName,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Selector: map[string]string{
				"app":       actor.id,
				"namespace": actor.namespace,
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
	svc, err := Clientset.CoreV1().Services(actor.namespace).Create(ctx, svcSpec, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create service in namespace %s: %w", actor.namespace, err)
	}
	actor.services = append(actor.services, *svc)

	// Register endpoint
	actor.privEndpoints = append(actor.privEndpoints, fmt.Sprintf("%s.%s.svc.cluster.local", svcName, actor.namespace))

	return nil
}

func (actor *Actor) createIngress(asURL string, ctx context.Context) error {
	ingName := actor.id + "-ingress"
	svcName := actor.id + "-service"
	className := "aggregator-traefik"
	pathType := networkingv1.PathTypePrefix

	// Check if ingress already exists
	_, err := Clientset.NetworkingV1().Ingresses(actor.namespace).Get(ctx, ingName, metav1.GetOptions{})
	if err == nil {
		return fmt.Errorf("ingress %s already exists in namespace %s", ingName, actor.namespace)
	}

	// Specify Ingress
	ingSpec := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ingName,
			Namespace: actor.namespace,
			Annotations: map[string]string{
				"traefik.ingress.kubernetes.io/router.middlewares": "aggregator-app-ingress-uma@kubernetescrd",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: &className,
			Rules: []networkingv1.IngressRule{
				{
					Host: ExternalHost,
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/actors/" + actor.namespace + "/" + actor.id,
									PathType: &pathType,
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: svcName,
											Port: networkingv1.ServiceBackendPort{
												Number: 80,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// Create Ingress
	ing, err := Clientset.NetworkingV1().Ingresses(actor.namespace).Create(ctx, ingSpec, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create ingress %s: %w", ingName, err)
	}
	actor.ingresses = append(actor.ingresses, *ing)

	// Register resource
	resourceID := fmt.Sprintf("http://%s/actors/%s/%s", ExternalHost, actor.namespace, actor.id)
	if err := registerResource(resourceID, asURL); err != nil {
		return fmt.Errorf("failed to register resource for ingress %q: %w", ingName, err)
	}

	// Register endpoint
	actor.pubEndpoints = append(actor.pubEndpoints, resourceID)

	logrus.Infof("Ingress %s created successfully in namespace %s", ingName, actor.namespace)
	return nil
}

func (actor *Actor) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Delete Deployments
	for _, dep := range actor.deployments {
		err := Clientset.AppsV1().Deployments(actor.namespace).Delete(ctx, dep.Name, metav1.DeleteOptions{})
		if err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete deployment %s: %w", dep.Name, err)
		}
	}

	// Delete Services
	for _, svc := range actor.services {
		err := Clientset.CoreV1().Services(actor.namespace).Delete(ctx, svc.Name, metav1.DeleteOptions{})
		if err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete service %s: %w", svc.Name, err)
		}
	}

	// Delete Ingresses
	for _, ing := range actor.ingresses {
		err := Clientset.NetworkingV1().Ingresses(actor.namespace).Delete(ctx, ing.Name, metav1.DeleteOptions{})
		if err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete ingress %s: %w", ing.Name, err)
		}
	}

	return nil
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
		ID:          actor.id,
		Description: actor.description,
		Namespace:   actor.namespace,
		Config:      fmt.Sprintf("http://%s/config/%s/actors/%s", ExternalHost, actor.namespace, actor.id),
		Status:      fmt.Sprintf("http://%s/config/%s/actors/%s/status", ExternalHost, actor.namespace, actor.id),
		Endpoints:   actor.pubEndpoints,
	}

	return json.Marshal(out)
}
