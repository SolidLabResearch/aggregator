package registration

import (
	"aggregator/types"
	"aggregator/vars"
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func createNamespace(user types.User, ctx context.Context) (string, error) {
	nsName := uuid.NewString()
	// Create namespace with labels/annotations
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: nsName,
			Labels: map[string]string{
				"created-by":      "aggregator",
				"istio-injection": "enabled",
			},
			Annotations: map[string]string{
				"owner":  user.UserId,
				"as_url": user.AuthzServerURL,
			},
		},
	}

	_, err := vars.Clientset.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to create namespace %s: %w", nsName, err)
	}

	logrus.Infof("Namespace %s created successfully ✅", nsName)

	return nsName, nil
}

// createUMAProxy deploys the Egress UMA Deployment + Service using typed clientset
func createUMAProxy(replicas int32, namespace string, tokenEndpoint string, refreshToken string, ctx context.Context) error {
	// --- Deployment ---
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "egress-uma",
			Namespace: namespace,
			Labels: map[string]string{
				"app": "egress-uma",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "egress-uma",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": "egress-uma",
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:            "egress-uma",
							Image:           "egress-uma",
							ImagePullPolicy: corev1.PullNever,
							Ports: []corev1.ContainerPort{
								{ContainerPort: 8080},
							},
							Env: []corev1.EnvVar{
								{Name: "CLIENT_ID", Value: vars.ClientId},
								{Name: "CLIENT_SECRET", Value: vars.ClientSecret},
								{Name: "REFRESH_TOKEN", Value: refreshToken},
								{Name: "TOKEN_ENDPOINT", Value: tokenEndpoint},
								{Name: "LOG_LEVEL", Value: vars.LogLevel.String()},
							},
						},
					},
				},
			},
		},
	}

	_, err := vars.Clientset.AppsV1().Deployments(namespace).Create(ctx, deploy, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create Egress UMA deployment: %w", err)
	}
	logrus.Infof("Egress UMA deployment created in namespace %s ✅", namespace)

	// --- Service ---
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "egress-uma",
			Namespace: namespace,
			Labels: map[string]string{
				"app": "egress-uma",
			},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app": "egress-uma",
			},
			Ports: []corev1.ServicePort{
				{
					Port:       8080,
					TargetPort: intstr.FromInt32(8080),
				},
			},
			Type: corev1.ServiceTypeClusterIP,
		},
	}

	_, err = vars.Clientset.CoreV1().Services(namespace).Create(ctx, service, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create Egress UMA service: %w", err)
	}
	logrus.Infof("Egress UMA service created in namespace %s ✅", namespace)

	return nil
}
