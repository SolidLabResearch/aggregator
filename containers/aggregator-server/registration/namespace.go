package registration

import (
	"aggregator/model"
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func createNamespaceForAggregator(ownerWebID string, authzServerURL string, ctx context.Context) (string, error) {
	nsName := uuid.NewString()
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: nsName,
			Labels: map[string]string{
				"created-by":      "aggregator",
				"istio-injection": "enabled",
			},
			Annotations: map[string]string{
				"owner":  ownerWebID,
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
func deployAggregatorResources(namespace string, tokenEndpoint string, accessToken string, refreshToken string, accessTokenExpiry string, ownerWebID string, authzServerURL string, ctx context.Context) error {
	replicas := int32(1)
	useUMA := authzServerURL != ""
	var err error

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
		umaDeploy := &appsv1.Deployment{
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

	// --- Aggregator Instance Deployment ---
	aggDeploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "aggregator",
			Namespace: namespace,
			Labels: map[string]string{
				"app": "aggregator",
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
					ServiceAccountName: "aggregator-sa", // Needs permissions? Maybe a new SA per user?
					Containers: []corev1.Container{
						{
							Name:            "aggregator",
							Image:           "aggregator", // The instance image
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
								{Name: "USER_ID", Value: ownerWebID},
								{Name: "AS_URL", Value: authzServerURL},
							},
						},
					},
				},
			},
		},
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
	aggDeploy.Spec.Template.Spec.ServiceAccountName = "aggregator-instance-sa"

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

	traefikRole := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "aggregator-instance-traefik-editor",
			Namespace: namespace,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"traefik.io"},
				Resources: []string{"ingressroutes", "middlewares"},
				Verbs:     []string{"get", "list", "create", "update", "delete"},
			},
		},
	}
	if _, err := model.Clientset.RbacV1().Roles(namespace).Create(ctx, traefikRole, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("failed to create Traefik Role: %w", err)
	}

	traefikBinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "aggregator-instance-traefik-binding",
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
			Name:     traefikRole.Name,
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
	if _, err := model.Clientset.RbacV1().RoleBindings(namespace).Create(ctx, traefikBinding, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("failed to create Traefik RoleBinding: %w", err)
	}

	if err := ensureConfigMap(namespace, "aggregator-instance-config", map[string]string{"access_token_expiry": accessTokenExpiry}, ctx); err != nil {
		return fmt.Errorf("failed to ensure instance configmap: %w", err)
	}

	_, err = model.Clientset.AppsV1().Deployments(namespace).Create(ctx, aggDeploy, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create Aggregator Instance deployment: %w", err)
	}
	logrus.Infof("Aggregator Instance deployment created in namespace %s ✅", namespace)

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

	ingressRouteGVR := schema.GroupVersionResource{
		Group:    "traefik.io",
		Version:  "v1alpha1",
		Resource: "ingressroutes",
	}

	irName := "aggregator-instance-ingressroute"
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
						"match": "Host(`" + model.ExternalHost + "`) && (Path(`/config/" + namespace + "`) || Path(`/config/" + namespace + "/`))",
						"kind":  "Rule",
						"services": []interface{}{
							map[string]interface{}{
								"name":      "aggregator",
								"port":      5000,
								"namespace": namespace,
							},
						},
						"middlewares": buildIngressMiddlewares(useUMA, namespace, true),
					},
					map[string]interface{}{
						"match": "Host(`" + model.ExternalHost + "`) && PathPrefix(`/config/" + namespace + "/actors`)",
						"kind":  "Rule",
						"services": []interface{}{
							map[string]interface{}{
								"name":      "aggregator",
								"port":      5000,
								"namespace": namespace,
							},
						},
						"middlewares": buildIngressMiddlewares(useUMA, namespace, false),
					},
					map[string]interface{}{
						"match": "Host(`" + model.ExternalHost + "`) && PathPrefix(`/config/" + namespace + "/transformations`)",
						"kind":  "Rule",
						"services": []interface{}{
							map[string]interface{}{
								"name":      "aggregator",
								"port":      5000,
								"namespace": namespace,
							},
						},
						"middlewares": buildIngressMiddlewares(useUMA, namespace, true),
					},
				},
			},
		},
	}

	// We need to create the strip-prefix middleware in the user namespace
	mwName := "strip-prefix-" + namespace
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
				"stripPrefix": map[string]interface{}{
					"prefixes": []string{"/config/" + namespace},
				},
			},
		},
	}

	_, err = model.DynamicClient.Resource(middlewareGVR).Namespace(namespace).Create(ctx, mwObj, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create Middleware: %w", err)
	}

	_, err = model.DynamicClient.Resource(ingressRouteGVR).Namespace(namespace).Create(ctx, obj, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create IngressRoute: %w", err)
	}

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
		if err := ensureConfigMap(namespace, "aggregator-instance-config", map[string]string{"access_token_expiry": accessTokenExpiry}, ctx); err != nil {
			return fmt.Errorf("failed to update instance configmap: %w", err)
		}
	}

	return nil
}

func buildIngressMiddlewares(useUMA bool, namespace string, includeStrip bool) []interface{} {
	middlewares := make([]interface{}, 0, 3)
	if useUMA {
		middlewares = append(middlewares, map[string]interface{}{
			"name":      "ingress-uma",
			"namespace": "aggregator-app",
		})
	}
	if includeStrip {
		middlewares = append(middlewares, map[string]interface{}{
			"name":      "strip-prefix-" + namespace,
			"namespace": namespace,
		})
	}
	middlewares = append(middlewares, map[string]interface{}{
		"name":      "cors",
		"namespace": "aggregator-app",
	})
	return middlewares
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
	return err
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
