package instance

import (
	"aggregator/model"
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func ensurePermissions(aggregatorId string, ctx context.Context) error {
	if err := ensureServiceAccount(aggregatorId, ctx); err != nil {
		return fmt.Errorf("failed to ensure service account: %w", err)
	}
	if err := ensureRoleBindings(aggregatorId, ctx); err != nil {
		return err
	}
	return nil
}

func ensureServiceAccount(aggregatorId string, ctx context.Context) error {
	saName := "aggregator-" + aggregatorId
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      saName,
			Namespace: model.Namespace,
		},
	}
	_, err := model.Clientset.CoreV1().ServiceAccounts(model.Namespace).Create(ctx, sa, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func ensureRoleBindings(aggregatorId string, ctx context.Context) error {
	saName := "aggregator-" + aggregatorId

	// Aggregator can manage fno services
	managerBinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("aggregator-%s-manager-binding", aggregatorId),
			Namespace: model.Namespace,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      saName,
				Namespace: model.Namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "Role",
			Name:     "aggregator-service-manager",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}

	_, err := model.Clientset.RbacV1().RoleBindings(model.Namespace).Create(ctx, managerBinding, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create manager RoleBinding: %w", err)
	}

	// Aggregator can read the server transformations
	tfBinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("aggregator-%s-tf-reader-binding", aggregatorId),
			Namespace: model.Namespace,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      saName,
				Namespace: model.Namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "Role",
			Name:     "aggregator-transformation-reader",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}

	if _, err := model.Clientset.RbacV1().RoleBindings(model.Namespace).Create(ctx, tfBinding, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("failed to create Transformation RoleBinding: %w", err)
	}

	return nil
}
