package registration

import (
	"aggregator/model"
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
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
func deployAggregatorResources(namespace string, tokenEndpoint string, refreshToken string, ownerWebID string, authzServerURL string, ctx context.Context) error {
	replicas := int32(1)

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
								{Name: "REFRESH_TOKEN", Value: refreshToken},
								{Name: "TOKEN_ENDPOINT", Value: tokenEndpoint},
								{Name: "LOG_LEVEL", Value: model.LogLevel.String()},
							},
						},
					},
				},
			},
		},
	}

	_, err := model.Clientset.AppsV1().Deployments(namespace).Create(ctx, umaDeploy, metav1.CreateOptions{})
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
						"match": "Host(`" + model.ExternalHost + "`) && PathPrefix(`/config/" + namespace + "`)",
						"kind":  "Rule",
						"services": []interface{}{
							map[string]interface{}{
								"name":      "aggregator",
								"port":      5000,
								"namespace": namespace,
							},
						},
						"middlewares": []interface{}{
							map[string]interface{}{
								"name":      "cors",
								"namespace": "aggregator-app",
							},
						},
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
						"middlewares": []interface{}{
							map[string]interface{}{
								"name":      "strip-prefix-" + namespace, // We need to create this middleware
								"namespace": namespace,
							},
							map[string]interface{}{
								"name":      "cors",
								"namespace": "aggregator-app",
							},
						},
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
