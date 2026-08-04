package instance

import (
	"aggregator/model"
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
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
	saName := "sa-" + aggregatorId
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      saName,
			Namespace: model.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by":        "aggregator-instance",
				"agg.knows.idlab.ugent.be/managed-by": aggregatorId,
				"agg.knows.idlab.ugent.be/id":         saName,
			},
		},
	}
	_, err := model.Clientset.CoreV1().ServiceAccounts(model.Namespace).Create(ctx, sa, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	return nil
}

func ensureRoleBindings(aggregatorId string, ctx context.Context) error {
	saName := "sa-" + aggregatorId
	// Aggregator can manage fno services
	managerBinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-manager-binding", aggregatorId),
			Namespace: model.Namespace,
			Labels: map[string]string{
				"agg.knows.idlab.ugent.be/managed-by": aggregatorId,
			},
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

	return nil
}
