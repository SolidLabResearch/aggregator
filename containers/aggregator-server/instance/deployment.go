package instance

import (
	"aggregator/model"
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func ensureDeployment(aggregatorId string, replicas int32, userId string, asURL string, ctx context.Context) error {
	aggName := "aggregator-" + aggregatorId

	// Aggregator Service
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      aggName,
			Namespace: model.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":              "aggregator-instance",
				"app.kubernetes.io/components":        "server",
				"app.kubernetes.io/part-of":           "aggregator-platform",
				"app.kubernetes.io/managed-by":        "aggregator-server",
				"agg.knows.idlab.ugent.be/managed-by": model.Namespace,
				"agg.knows.idlab.ugent.be/id":         aggregatorId,
			},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app.kubernetes.io/name":              "aggregator-instance",
				"app.kubernetes.io/components":        "server",
				"agg.knows.idlab.ugent.be/managed-by": model.Namespace,
				"agg.knows.idlab.ugent.be/id":         aggregatorId,
			},
			Ports: []corev1.ServicePort{
				{
					Protocol:   corev1.ProtocolTCP,
					Port:       5000,
					TargetPort: intstr.FromInt(5000),
				},
			},
		},
	}

	_, err := model.Clientset.CoreV1().Services(model.Namespace).Create(ctx, service, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create service: %w", err)
	}

	// Aggregator Ingress
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      aggName,
			Namespace: model.Namespace,
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: model.IngressClassName,
			Rules: []networkingv1.IngressRule{
				{
					Host: model.ExternalHost,
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/" + aggregatorId,
									PathType: func() *networkingv1.PathType { pt := networkingv1.PathTypePrefix; return &pt }(),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: aggName,
											Port: networkingv1.ServiceBackendPort{
												Number: 5000,
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

	_, err = model.Clientset.NetworkingV1().Ingresses(model.Namespace).Create(ctx, ingress, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create ingress: %w", err)
	}

	// Aggregator deployment
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      aggName,
			Namespace: model.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":              "aggregator-instance",
				"app.kubernetes.io/components":        "server",
				"app.kubernetes.io/part-of":           "aggregator-platform",
				"app.kubernetes.io/managed-by":        "aggregator-server",
				"agg.knows.idlab.ugent.be/managed-by": model.Namespace,
				"agg.knows.idlab.ugent.be/id":         aggregatorId,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app.kubernetes.io/name":              "aggregator-instance",
					"app.kubernetes.io/components":        "server",
					"agg.knows.idlab.ugent.be/managed-by": model.Namespace,
					"agg.knows.idlab.ugent.be/id":         aggregatorId,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app.kubernetes.io/name":              "aggregator-instance",
						"app.kubernetes.io/components":        "server",
						"app.kubernetes.io/part-of":           "aggregator-platform",
						"app.kubernetes.io/managed-by":        "aggregator-server",
						"agg.knows.idlab.ugent.be/managed-by": model.Namespace,
						"agg.knows.idlab.ugent.be/id":         aggregatorId,
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: aggName,
					Containers: []corev1.Container{
						{
							Name:            aggName,
							Image:           "aggregator",
							ImagePullPolicy: corev1.PullNever,
							Ports: []corev1.ContainerPort{
								{ContainerPort: 5000},
							},
							Env: []corev1.EnvVar{
								{Name: "AGGREGATOR_EXTERNAL_HOST", Value: model.ExternalHost},
								{Name: "CLIENT_ID", Value: model.ClientId},
								{Name: "CLIENT_SECRET", Value: model.ClientSecret},
								{Name: "LOG_LEVEL", Value: model.LogLevel.String()},
								{Name: "ID", Value: aggregatorId},
								{Name: "NAMESPACE", Value: model.Namespace},
								{Name: "USER_ID", Value: userId},
								{Name: "AS_URL", Value: asURL},
								{Name: "TRANSFORMATION_CATALOG", Value: model.TransformationCatalog},
								{Name: "SERVICE_COLLECTION", Value: model.ServiceCollection},
							},
						},
					},
				},
			},
		},
	}

	_, err = model.Clientset.AppsV1().Deployments(model.Namespace).Create(ctx, deployment, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create deployment: %w", err)
	}
	return nil
}
