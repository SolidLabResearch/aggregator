package registration

import (
	"aggregator/model"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func createNamespaceForAggregator(ownerID string, authzServerURL string, ctx context.Context) (string, error) {
	nsName := uuid.NewString()
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: nsName,
			Labels: map[string]string{
				"aggregator.idlab/created-by": model.Namespace,
				"istio-injection":             "enabled",
			},
			Annotations: map[string]string{
				"owner":  ownerID,
				"as_url": authzServerURL,
			},
		},
	}

	_, err := model.Clientset.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to create namespace %s: %w", nsName, err)
	}

	logrus.Infof("Namespace %s created for aggregator ✅", nsName)
	return nsName, nil
}

func resolveOwnerID(ownerID string, namespace string) string {
	trimmed := strings.TrimSpace(ownerID)
	if trimmed != "" {
		return trimmed
	}
	return fmt.Sprintf("urn:aggregator:%s", namespace)
}

// deleteNamespaceResources deletes a namespace and all its resources
func deleteNamespaceResources(namespace string, ctx context.Context) error {
	err := model.Clientset.CoreV1().Namespaces().Delete(ctx, namespace, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete namespace %s: %w", namespace, err)
	}

	logrus.Infof("Namespace %s deleted ✅", namespace)
	return nil
}

// deployAggregatorResources deploys the Egress UMA and Aggregator Instance
func deployAggregatorResources(
	namespace string,
	tokenEndpoint string,
	accessToken string,
	refreshToken string,
	accessTokenExpiry string,
	ownerID string,
	authzServerURL string,
	ctx context.Context,
) error {
	aggregatorId := uuid.NewString()
	replicas := int32(1)
	useUMA := authzServerURL != ""
	var err error
	resolvedOwner := resolveOwnerID(ownerID, aggregatorId)

	if useUMA {
		if err := ensureEgressUMARbac(namespace, ctx); err != nil {
			return fmt.Errorf("failed to ensure egress-uma RBAC: %w", err)
		}

		tokensPayload, err := buildTokensPayload(accessToken, refreshToken, accessTokenExpiry)
		if err != nil {
			return fmt.Errorf("failed to build egress-uma token payload: %w", err)
		}
		if err := ensureConfigMap(namespace, "egress-uma-config", tokensPayload, ctx); err != nil {
			return fmt.Errorf("failed to ensure egress-uma configmap: %w", err)
		}

		// --- Egress UMA Deployment ---
		egressName := fmt.Sprintf("%s-egress-uma", aggregatorId)
		umaDeploy := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      egressName,
				Namespace: model.Namespace,
				Labels: map[string]string{
					"app": egressName,
				},
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: &replicas,
				Selector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app": egressName,
					},
				},
				Template: corev1.PodTemplateSpec{
					ObjectMeta: metav1.ObjectMeta{
						Labels: map[string]string{
							"app": egressName,
						},
					},
					Spec: corev1.PodSpec{
						ServiceAccountName: "egress-uma-sa",
						Containers: []corev1.Container{
							{
								Name:            "egress-uma",
								Image:           "egress-uma",
								ImagePullPolicy: corev1.PullNever,
								Ports: []corev1.ContainerPort{
									{ContainerPort: 8080},
								},
								Env: []corev1.EnvVar{
									{Name: "CLIENT_ID", Value: model.ClientId},
									{Name: "CLIENT_SECRET", Value: model.ClientSecret},
									{Name: "TOKEN_ENDPOINT", Value: tokenEndpoint},
									{Name: "UPDATE_TOKENS_FILE", Value: "/etc/egress-uma/tokens.json"},
									{Name: "LOG_LEVEL", Value: model.LogLevel.String()},
								},
								VolumeMounts: []corev1.VolumeMount{
									{
										Name:      "egress-uma-config",
										MountPath: "/etc/egress-uma",
										ReadOnly:  true,
									},
								},
							},
						},
						Volumes: []corev1.Volume{
							{
								Name: "egress-uma-config",
								VolumeSource: corev1.VolumeSource{
									ConfigMap: &corev1.ConfigMapVolumeSource{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "egress-uma-config",
										},
									},
								},
							},
						},
					},
				},
			},
		}

		_, err = model.Clientset.AppsV1().Deployments(namespace).Create(ctx, umaDeploy, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed to create Egress UMA deployment: %w", err)
		}
		logrus.Infof("Egress UMA deployment created in namespace %s ✅", namespace)

		// --- Egress UMA Service ---
		umaService := &corev1.Service{
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
						Protocol:   corev1.ProtocolTCP,
						Port:       8080,
						TargetPort: intstr.FromInt(8080),
					},
				},
			},
		}

		_, err = model.Clientset.CoreV1().Services(namespace).Create(ctx, umaService, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed to create Egress UMA service: %w", err)
		}
	}

	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "aggregator-instance-sa",
			Namespace: namespace,
		},
	}
	_, err = model.Clientset.CoreV1().ServiceAccounts(namespace).Create(ctx, sa, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create ServiceAccount: %w", err)
	}

	roleBinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "aggregator-instance-admin-binding",
			Namespace: namespace,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      sa.Name,
				Namespace: namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "admin",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}

	_, err = model.Clientset.RbacV1().RoleBindings(namespace).Create(ctx, roleBinding, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create RoleBinding: %w", err)
	}

	// Aggregator can read transformations from server namespace
	transformationBinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("aggregator-transformation-reader-binding-%s", namespace),
			Namespace: model.Namespace,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      sa.Name,
				Namespace: namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "Role",
			Name:     "aggregator-transformation-reader",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}

	if _, err := model.Clientset.RbacV1().RoleBindings(model.Namespace).Create(ctx, transformationBinding, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("failed to create Transformation RoleBinding: %w", err)
	}

	if err := ensureConfigMap(namespace, "aggregator-instance-config", map[string]string{
		"access_token_expiry": accessTokenExpiry,
		"created_at":          time.Now().Format(time.RFC3339),
	}, ctx); err != nil {
		return fmt.Errorf("failed to ensure instance configmap: %w", err)
	}

	// --- Aggregator Instance Service ---
	aggService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "aggregator",
			Namespace: namespace,
			Labels: map[string]string{
				"app": "aggregator",
			},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app": "aggregator",
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

	_, err = model.Clientset.CoreV1().Services(namespace).Create(ctx, aggService, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create Aggregator Instance service: %w", err)
	}

	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "aggregator-instance-ingress",
			Namespace: namespace,
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
									Path:     "/" + namespace,
									PathType: func() *networkingv1.PathType { pt := networkingv1.PathTypePrefix; return &pt }(),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "aggregator",
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

	_, err = model.Clientset.NetworkingV1().Ingresses(namespace).Create(ctx, ingress, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create Ingress: %w", err)
	}

	// --- Aggregator Instance Deployment ---
	aggDeploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "aggregator",
			Namespace: namespace,
			Labels: map[string]string{
				"app":        "aggregator",
				"created-by": model.Namespace,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "aggregator",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": "aggregator",
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: "aggregator-instance-sa",
					Containers: []corev1.Container{
						{
							Name:            "aggregator",
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
								{Name: "USER_NAMESPACE", Value: namespace},
								{Name: "SERVER_NAMESPACE", Value: model.Namespace},
								{Name: "USER_ID", Value: resolvedOwner},
								{Name: "AS_URL", Value: authzServerURL},
								{Name: "TRANSFORMATION_CATALOG", Value: os.Getenv("TRANSFORMATION_CATALOG")},
								{Name: "SERVICE_COLLECTION", Value: os.Getenv("SERVICE_COLLECTION")},
							},
						},
					},
				},
			},
		},
	}

	_, err = model.Clientset.AppsV1().Deployments(namespace).Create(ctx, aggDeploy, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create Aggregator Instance deployment: %w", err)
	}
	logrus.Infof("Aggregator Instance deployment created in namespace %s ✅", namespace)

	return nil
}

func updateAggregatorInstanceDeployments(namespace string, accessToken string, refreshToken string, accessTokenExpiry string, ctx context.Context) error {
	if model.Clientset == nil {
		logrus.Warn("Kubernetes client not initialized; skipping instance deployment updates")
		return nil
	}

	if accessToken != "" || refreshToken != "" {
		tokensPayload, err := buildTokensPayload(accessToken, refreshToken, accessTokenExpiry)
		if err != nil {
			return fmt.Errorf("failed to build egress-uma token payload: %w", err)
		}
		if err := ensureConfigMap(namespace, "egress-uma-config", tokensPayload, ctx); err != nil {
			return fmt.Errorf("failed to update egress-uma configmap: %w", err)
		}
	}

	if accessTokenExpiry != "" {
		if err := ensureConfigMap(namespace, "aggregator-instance-config", map[string]string{
			"access_token_expiry": accessTokenExpiry,
		}, ctx); err != nil {
			return fmt.Errorf("failed to update instance configmap: %w", err)
		}
	}

	return nil
}

func buildTokensPayload(accessToken string, refreshToken string, accessTokenExpiry string) (map[string]string, error) {
	payload := map[string]string{
		"access_token":        accessToken,
		"refresh_token":       refreshToken,
		"access_token_expiry": accessTokenExpiry,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return map[string]string{"tokens.json": string(data)}, nil
}

func ensureConfigMap(namespace string, name string, data map[string]string, ctx context.Context) error {
	if len(data) == 0 {
		return fmt.Errorf("configmap data is required")
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: data,
	}

	_, err := model.Clientset.CoreV1().ConfigMaps(namespace).Create(ctx, cm, metav1.CreateOptions{})
	if err == nil {
		return nil
	}
	if !apierrors.IsAlreadyExists(err) {
		return err
	}

	var lastErr error
	for i := 0; i < 3; i++ {
		existing, err := model.Clientset.CoreV1().ConfigMaps(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if existing.Data == nil {
			existing.Data = map[string]string{}
		}
		for key, value := range data {
			if value == "" {
				continue
			}
			existing.Data[key] = value
		}
		_, err = model.Clientset.CoreV1().ConfigMaps(namespace).Update(ctx, existing, metav1.UpdateOptions{})
		if err == nil {
			return nil
		}
		if !apierrors.IsConflict(err) {
			return err
		}
		lastErr = err
	}
	return lastErr
}

func ensureEgressUMARbac(namespace string, ctx context.Context) error {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "egress-uma-sa",
			Namespace: namespace,
		},
	}
	if _, err := model.Clientset.CoreV1().ServiceAccounts(namespace).Create(ctx, sa, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}

	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "egress-uma-configmap-editor",
			Namespace: namespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"get", "list", "create", "update", "patch"},
			},
		},
	}
	if _, err := model.Clientset.RbacV1().Roles(namespace).Create(ctx, role, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}

	roleBinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "egress-uma-configmap-binding",
			Namespace: namespace,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      sa.Name,
				Namespace: namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "Role",
			Name:     role.Name,
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
	if _, err := model.Clientset.RbacV1().RoleBindings(namespace).Create(ctx, roleBinding, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}

	return nil
}
