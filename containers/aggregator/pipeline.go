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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

type Pipeline struct {
	Metadata    PipelineRequest        `json:"metadata"`
	Namespace   string                 `json:"namespace"`
	Deployments []appsv1.Deployment    `json:"deployments"`
	Services    []corev1.Service       `json:"services"`
	Ingresses   []networkingv1.Ingress `json:"ingresses"`
}

func setupPipeline(request PipelineRequest) (*Pipeline, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pipeline := Pipeline{
		Metadata:    request,
		Namespace:   request.Name,
		Deployments: []appsv1.Deployment{},
		Services:    []corev1.Service{},
		Ingresses:   []networkingv1.Ingress{},
	}

	err := pipeline.createNamespace(ctx)
	if err != nil {
		return nil, fmt.Errorf("namespace creation failed: %w", err)
	}

	err = pipeline.createDeployment(1, ctx)
	if err != nil {
		return nil, fmt.Errorf("pod creation failed: %w", err)
	}

	err = pipeline.createService(ctx)
	if err != nil {
		return nil, fmt.Errorf("service creation failed: %w", err)
	}

	err = pipeline.createIngress(ctx)
	if err != nil {
		return nil, fmt.Errorf("ingress creation failed: %w", err)
	}

	// Wait for pipeline Ready
	pipeline.waitReady(ctx, 120*time.Second)

	return &pipeline, err
}

func (pipeline Pipeline) createNamespace(ctx context.Context) error {
	// Check if namespace already exists
	_, err := Clientset.CoreV1().Namespaces().Get(ctx, pipeline.Namespace, metav1.GetOptions{})
	if err == nil {
		return fmt.Errorf("namespace %s already exists", pipeline.Namespace)
	}

	// Create namespace with labels/annotations
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: pipeline.Namespace,
			Labels: map[string]string{
				"created-by": "aggregator",
			},
			Annotations: map[string]string{
				"owner":  pipeline.Metadata.Owner.WebID,
				"as_url": pipeline.Metadata.Owner.ASURL,
			},
		},
	}

	_, err = Clientset.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create namespace %s: %w", pipeline.Namespace, err)
	}

	logrus.Infof("Namespace %s created successfully ✅", pipeline.Namespace)

	return nil
}

func (pipeline *Pipeline) createDeployment(replicas int32, ctx context.Context) error {
	labels := map[string]string{
		"app":       pipeline.Metadata.Name,
		"namespace": pipeline.Namespace,
	}

	container := corev1.Container{
		Name:            pipeline.Metadata.Name,
		Image:           "echo",
		ImagePullPolicy: corev1.PullNever,
		Env: []corev1.EnvVar{
			{Name: "PIPELINE_DESCRIPTION", Value: pipeline.Metadata.Description},
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
			Name:      pipeline.Metadata.Name,
			Namespace: pipeline.Namespace,
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

	deploy, err := Clientset.AppsV1().Deployments(pipeline.Namespace).Create(ctx, deploySpec, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create deployment %s: %w", pipeline.Metadata.Name, err)
	}
	pipeline.Deployments = append(pipeline.Deployments, *deploy)

	logrus.Infof("Deployment %s created successfully in namespace %s", pipeline.Metadata.Name, pipeline.Namespace)
	return nil
}

func (pipeline *Pipeline) createService(ctx context.Context) error {
	svcName := pipeline.Metadata.Name + "-service"

	// Check if service already exists
	_, err := Clientset.CoreV1().Services(pipeline.Namespace).Get(ctx, svcName, metav1.GetOptions{})
	if err == nil {
		return fmt.Errorf("service %s already exists in namespace %s", svcName, pipeline.Namespace)
	}

	// ----------------------------
	// 1. Specify Service
	// ----------------------------
	svcSpec := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: svcName,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Selector: map[string]string{
				"app":       pipeline.Metadata.Name,
				"namespace": pipeline.Namespace,
			},
			Ports: []corev1.ServicePort{
				{
					Port:       80,
					TargetPort: intstr.FromInt(8080),
				},
			},
		},
	}

	// ----------------------------
	// 1. Create Service
	// ----------------------------
	svc, err := Clientset.CoreV1().Services(pipeline.Namespace).Create(ctx, svcSpec, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create service in namespace %s: %w", pipeline.Namespace, err)
	}
	pipeline.Services = append(pipeline.Services, *svc)

	return nil
}

func (pipeline *Pipeline) createIngress(ctx context.Context) error {
	ingName := pipeline.Metadata.Name + "-ingress"
	svcName := pipeline.Metadata.Name + "-service"
	className := "nginx"
	pathType := networkingv1.PathTypePrefix

	// Check if ingress already exists
	_, err := Clientset.NetworkingV1().Ingresses(pipeline.Namespace).Get(ctx, ingName, metav1.GetOptions{})
	if err == nil {
		return fmt.Errorf("ingress %s already exists in namespace %s", ingName, pipeline.Namespace)
	}

	// ----------------------------
	// 1. Specify Ingress
	// ----------------------------
	ingSpec := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ingName,
			Namespace: pipeline.Namespace,
			Annotations: map[string]string{
				"nginx.ingress.kubernetes.io/auth-url":       "http://ingress-uma.aggregator-ns.svc.cluster.local/authorize",
				"nginx.ingress.kubernetes.io/rewrite-target": "/",
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
									Path:     "/actors/" + pipeline.Namespace,
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

	// ----------------------------
	// Register resource
	// ----------------------------
	resourceID := fmt.Sprintf("http://%s/actors/%s", ExternalHost, pipeline.Metadata.Name)
	if err := registerResource(resourceID, pipeline.Metadata.Owner.ASURL); err != nil {
		return fmt.Errorf("failed to register resource %q for ingress %q: %w", resourceID, ingName, err)
	}

	// ----------------------------
	// 1. Create Ingress
	// ----------------------------
	ing, err := Clientset.NetworkingV1().Ingresses(pipeline.Namespace).Create(ctx, ingSpec, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create ingress %s: %w", ingName, err)
	}
	pipeline.Ingresses = append(pipeline.Ingresses, *ing)

	logrus.Infof("Ingress %s created successfully in namespace %s", ingName, pipeline.Namespace)
	return nil
}

func (pipeline *Pipeline) waitReady(ctx context.Context, timeout time.Duration) error {
	if len(pipeline.Deployments) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for deployments to be ready")
		case <-ticker.C:
			allReady := true

			for _, deploy := range pipeline.Deployments {
				desired := int32(1) // default to 1
				if deploy.Spec.Replicas != nil {
					desired = *deploy.Spec.Replicas
				}

				if deploy.Status.AvailableReplicas < desired {
					allReady = false
					break
				}
			}

			if allReady {
				logrus.Infof("All deployments in namespace %s are ready ✅", pipeline.Namespace)
				return nil
			}
		}
	}
}

func (p *Pipeline) Stop() error {
	if p.Namespace == "" {
		return fmt.Errorf("pipeline namespace is empty")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Delete the namespace
	err := Clientset.CoreV1().Namespaces().Delete(ctx, p.Namespace, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete namespace %s: %w", p.Namespace, err)
	}
	logrus.Infof("Deleting namespace %s...", p.Namespace)

	// Wait for namespace to terminate
	for {
		_, err := Clientset.CoreV1().Namespaces().Get(ctx, p.Namespace, metav1.GetOptions{})
		if err != nil {
			logrus.Infof("Namespace %s deleted successfully", p.Namespace)
			break
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for namespace %s to terminate", p.Namespace)
		case <-time.After(2 * time.Second):
			// Retry
		}
	}

	return nil
}

func (p *Pipeline) MarshalJSON() ([]byte, error) {
	type deploymentStatusDTO struct {
		Name            string `json:"name"`
		ReadyReplicas   int32  `json:"ready_replicas"`
		DesiredReplicas int32  `json:"desired_replicas"`
		Status          string `json:"status"`
	}

	type pipelineDTO struct {
		Metadata    PipelineRequest       `json:"metadata"`
		Deployments []deploymentStatusDTO `json:"deployments"`
		Endpoints   []string              `json:"endpoints"`
	}

	var deploymentsInfo []deploymentStatusDTO

	// Collect status info for each deployment
	for _, d := range p.Deployments {
		deploymentsInfo = append(deploymentsInfo, deploymentStatusDTO{
			Name:            d.Name,
			ReadyReplicas:   d.Status.ReadyReplicas,
			DesiredReplicas: *d.Spec.Replicas,
			Status:          fmt.Sprintf("%+v", d.Status.Conditions),
		})
	}

	// Collect all reachable endpoints from all ingresses
	var endpoints []string
	for _, ing := range p.Ingresses {
		if ing.Spec.Rules == nil {
			continue
		}
		for _, rule := range ing.Spec.Rules {
			host := rule.Host
			if rule.HTTP == nil {
				continue
			}
			for _, path := range rule.HTTP.Paths {
				if host != "" {
					scheme := "http"
					// assume TLS if ingress has a TLS section for that host
					for _, tls := range ing.Spec.TLS {
						for _, tlsHost := range tls.Hosts {
							if tlsHost == host {
								scheme = "https"
								break
							}
						}
					}
					endpoints = append(endpoints, fmt.Sprintf("%s://%s%s", scheme, host, path.Path))
				}
			}
		}
	}

	dto := pipelineDTO{
		Metadata:    p.Metadata,
		Deployments: deploymentsInfo,
		Endpoints:   endpoints,
	}

	return json.Marshal(dto)
}
