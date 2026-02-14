package instance

import (
	"aggregator/model"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func DeployAggregator(
	ownerID string,
	authzServerURL string,
	provisionId string,
	ctx context.Context,
) (string, error) {
	aggregatorId := uuid.NewString()
	resolvedOwner := resolveOwnerID(ownerID, aggregatorId)

	if authzServerURL != "" {
		registerAsResourceServer(aggregatorId, ownerID, authzServerURL)
		// Deploy egress for the aggregator
		if err := ensureEgress(aggregatorId, ownerID, ctx); err != nil {
			return "", fmt.Errorf("failed to deploy uma egress for %s: %w", aggregatorId, err)
		}
		logrus.Infof("Deployed uma egress for %s", aggregatorId)
	}

	if err := ensurePermissions(aggregatorId, ctx); err != nil {
		return "", fmt.Errorf("failed to ensure permissions for %s: %w", aggregatorId, err)
	}
	logrus.Infof("Ensured permissions for %s", aggregatorId)

	cmName, err := ensureConfigMap(aggregatorId, "config", map[string]string{
		"created_at": time.Now().Format(time.RFC3339),
	}, ctx)
	if err != nil {
		return "", fmt.Errorf("failed to ensure instance configmap for %s: %w", aggregatorId, err)
	}
	logrus.Infof("Ensured configuration for %s", aggregatorId)

	if err := ensureDeployment(aggregatorId, 1, resolvedOwner, authzServerURL, provisionId, cmName, ctx); err != nil {
		return "", fmt.Errorf("failed to deploy aggregator %s: %w", aggregatorId, err)
	}
	logrus.Infof("Deployed aggregator %s", aggregatorId)

	return aggregatorId, nil
}

// deleteAggregator deletes an aggregator instance and its associated resources
func DeleteAggregator(aggregatorId string, ctx context.Context) error {
	// 1. Delete core resources
	if err := deleteAggregatorResources(aggregatorId, ctx); err != nil {
		return err
	}

	labelSelector := fmt.Sprintf(
		"app.kubernetes.io/name=aggregator-instance,agg.knows.idlab.ugent.be/managed-by=%s,agg.knows.idlab.ugent.be/id=%s",
		model.Namespace,
		aggregatorId,
	)
	deletePolicy := metav1.DeletePropagationForeground

	// 2. Delete Deployments
	if err := model.Clientset.AppsV1().Deployments(model.Namespace).DeleteCollection(ctx, metav1.DeleteOptions{
		PropagationPolicy: &deletePolicy,
	}, metav1.ListOptions{
		LabelSelector: labelSelector,
	}); err != nil {
		return fmt.Errorf("failed to delete aggregator deployments: %w", err)
	}

	// 3. Delete Services
	services, err := model.Clientset.CoreV1().Services(model.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return fmt.Errorf("failed to list aggregator services: %w", err)
	}
	for _, svc := range services.Items {
		if err := model.Clientset.CoreV1().Services(model.Namespace).Delete(ctx, svc.Name, metav1.DeleteOptions{
			PropagationPolicy: &deletePolicy,
		}); err != nil {
			return fmt.Errorf("failed to delete aggregator service %s: %w", svc.Name, err)
		}
	}

	// 4. Delete Ingresses
	ingresses, err := model.Clientset.NetworkingV1().Ingresses(model.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return fmt.Errorf("failed to list ingress resources: %w", err)
	}
	for _, ing := range ingresses.Items {
		if err := model.Clientset.NetworkingV1().Ingresses(model.Namespace).Delete(ctx, ing.Name, metav1.DeleteOptions{
			PropagationPolicy: &deletePolicy,
		}); err != nil {
			return fmt.Errorf("failed to delete ingress %s: %w", ing.Name, err)
		}
	}

	return nil
}

func UpdateAggregator(aggregatorId string, accessToken string, refreshToken string, accessTokenExpiry string, ctx context.Context) error {
	if model.Clientset == nil {
		logrus.Warn("Kubernetes client not initialized; skipping instance deployment updates")
		return nil
	}

	if accessToken != "" || refreshToken != "" {
		tokensPayload, err := buildTokensPayload(accessToken, refreshToken, accessTokenExpiry)
		if err != nil {
			return fmt.Errorf("failed to build egress-uma token payload: %w", err)
		}
		_, err = ensureConfigMap(aggregatorId, "egress-uma-config", tokensPayload, ctx)
		if err != nil {
			return fmt.Errorf("failed to update egress-uma configmap: %w", err)
		}
	}

	if accessTokenExpiry != "" {
		_, err := ensureConfigMap(aggregatorId, "config", map[string]string{
			"access_token_expiry": accessTokenExpiry,
		}, ctx)
		if err != nil {
			return fmt.Errorf("failed to update instance configmap: %w", err)
		}
	}

	return nil
}

func deleteAggregatorResources(aggregatorId string, ctx context.Context) error {
	labelSelector := fmt.Sprintf(
		"agg.knows.idlab.ugent.be/managed-by=%s",
		aggregatorId,
	)
	deletePolicy := metav1.DeletePropagationForeground

	// 1. Delete Deployments
	if err := model.Clientset.AppsV1().Deployments(model.Namespace).DeleteCollection(ctx, metav1.DeleteOptions{
		PropagationPolicy: &deletePolicy,
	}, metav1.ListOptions{
		LabelSelector: labelSelector,
	}); err != nil {
		return fmt.Errorf("failed to delete deployments: %w", err)
	}

	// 2. Delete Services
	services, err := model.Clientset.CoreV1().Services(model.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return fmt.Errorf("failed to list services: %w", err)
	}
	for _, svc := range services.Items {
		if err := model.Clientset.CoreV1().Services(model.Namespace).Delete(ctx, svc.Name, metav1.DeleteOptions{
			PropagationPolicy: &deletePolicy,
		}); err != nil {
			return fmt.Errorf("failed to delete service %s: %w", svc.Name, err)
		}
	}

	// 3. Delete ConfigMaps
	configMaps, err := model.Clientset.CoreV1().ConfigMaps(model.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return fmt.Errorf("failed to list configmaps: %w", err)
	}
	for _, cm := range configMaps.Items {
		if err := model.Clientset.CoreV1().ConfigMaps(model.Namespace).Delete(ctx, cm.Name, metav1.DeleteOptions{}); err != nil {
			return fmt.Errorf("failed to delete configmap %s: %w", cm.Name, err)
		}
	}

	// 4. Delete ServiceAccounts
	saList, err := model.Clientset.CoreV1().ServiceAccounts(model.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return fmt.Errorf("failed to list serviceaccounts: %w", err)
	}
	for _, sa := range saList.Items {
		if err := model.Clientset.CoreV1().ServiceAccounts(model.Namespace).Delete(ctx, sa.Name, metav1.DeleteOptions{}); err != nil {
			return fmt.Errorf("failed to delete serviceaccount %s: %w", sa.Name, err)
		}
	}

	// 5. Delete RoleBindings
	rbList, err := model.Clientset.RbacV1().RoleBindings(model.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return fmt.Errorf("failed to list rolebindings: %w", err)
	}
	for _, rb := range rbList.Items {
		if err := model.Clientset.RbacV1().RoleBindings(model.Namespace).Delete(ctx, rb.Name, metav1.DeleteOptions{}); err != nil {
			return fmt.Errorf("failed to delete rolebinding %s: %w", rb.Name, err)
		}
	}

	return nil
}

func resolveOwnerID(ownerID string, aggregatorId string) string {
	trimmed := strings.TrimSpace(ownerID)
	if trimmed != "" {
		return trimmed
	}
	return fmt.Sprintf("urn:aggregator:%s", aggregatorId)
}

func ensureConfigMap(aggregatorId string, name string, data map[string]string, ctx context.Context) (string, error) {
	cmName := name + "-" + aggregatorId
	if len(data) == 0 {
		return cmName, fmt.Errorf("configmap data is required")
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cmName,
			Namespace: model.Namespace,
			Labels: map[string]string{
				"agg.knows.idlab.ugent.be/managed-by": aggregatorId,
			},
		},
		Data: data,
	}

	_, err := model.Clientset.CoreV1().ConfigMaps(model.Namespace).Create(ctx, cm, metav1.CreateOptions{})
	if err == nil {
		return cmName, nil
	}
	if !apierrors.IsAlreadyExists(err) {
		return cmName, err
	}

	var lastErr error
	for i := 0; i < 3; i++ {
		existing, err := model.Clientset.CoreV1().ConfigMaps(model.Namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return cmName, err
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
		_, err = model.Clientset.CoreV1().ConfigMaps(model.Namespace).Update(ctx, existing, metav1.UpdateOptions{})
		if err == nil {
			return cmName, nil
		}
		if !apierrors.IsConflict(err) {
			return cmName, err
		}
		lastErr = err
	}
	return cmName, lastErr
}

// Register the aggregator server as resource server
func registerAsResourceServer(aggregatorID string, ownerID string, authzServerURL string) error {
	// Register the aggregator as RS at the AS
	payload := map[string]string{
		"aggregator_id": aggregatorID,
		"user_id":       ownerID,
		"as_url":        authzServerURL,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		logrus.Errorf("Failed to marshal registration payload: %v", err)
		return err
	}

	registrationURL := fmt.Sprintf("http://ingress-uma.%s.svc.cluster.local:8080/register", model.Namespace)
	req, err := http.NewRequest("POST", registrationURL, bytes.NewBuffer(body))
	if err != nil {
		logrus.Errorf("Failed to create registration request: %v", err)
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := model.HttpClient.Do(req)
	if err != nil {
		logrus.Errorf("Failed to send registration request: %v", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logrus.Errorf("Registration failed with status %d", resp.StatusCode)
		return fmt.Errorf("registration failed: status %d", resp.StatusCode)
	}

	logrus.Info("Aggregator registered successfully as RS")
	return nil
}
