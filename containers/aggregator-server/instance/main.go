package instance

import (
	"aggregator/model"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func DeployAggregator(
	tokenEndpoint string,
	accessToken string,
	refreshToken string,
	accessTokenExpiry string,
	ownerID string,
	authzServerURL string,
	ctx context.Context,
) (string, error) {
	aggregatorId := uuid.NewString()
	resolvedOwner := resolveOwnerID(ownerID, aggregatorId)

	if authzServerURL != "" {
		if err := ensureEgress(aggregatorId, tokenEndpoint, accessToken, refreshToken, accessTokenExpiry, ctx); err != nil {
			return "", fmt.Errorf("failed to deploy uma egress for %s: %w", aggregatorId, err)
		}
		logrus.Infof("Deployed uma egress for %s", aggregatorId)
	}

	if err := ensurePermissions(aggregatorId, ctx); err != nil {
		return "", fmt.Errorf("failed to ensure permissions for %s: %w", aggregatorId, err)
	}
	logrus.Infof("Ensured permissions for %s", aggregatorId)

	configName := "aggregator-" + aggregatorId + "-config"
	if err := ensureConfigMap(configName, map[string]string{
		"access_token_expiry": accessTokenExpiry,
		"created_at":          time.Now().Format(time.RFC3339),
	}, ctx); err != nil {
		return "", fmt.Errorf("failed to ensure instance configmap for %s: %w", aggregatorId, err)
	}
	logrus.Infof("Ensured configuration for %s", aggregatorId)

	if err := ensureDeployment(aggregatorId, 1, resolvedOwner, authzServerURL, ctx); err != nil {
		return "", fmt.Errorf("failed to deploy aggregator %s: %w", aggregatorId, err)
	}
	logrus.Infof("Deployed aggregator %s", aggregatorId)

	return aggregatorId, nil
}

func resolveOwnerID(ownerID string, aggregatorId string) string {
	trimmed := strings.TrimSpace(ownerID)
	if trimmed != "" {
		return trimmed
	}
	return fmt.Sprintf("urn:aggregator:%s", aggregatorId)
}

func ensureConfigMap(name string, data map[string]string, ctx context.Context) error {
	if len(data) == 0 {
		return fmt.Errorf("configmap data is required")
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: model.Namespace,
		},
		Data: data,
	}

	_, err := model.Clientset.CoreV1().ConfigMaps(model.Namespace).Create(ctx, cm, metav1.CreateOptions{})
	if err == nil {
		return nil
	}
	if !apierrors.IsAlreadyExists(err) {
		return err
	}

	var lastErr error
	for i := 0; i < 3; i++ {
		existing, err := model.Clientset.CoreV1().ConfigMaps(model.Namespace).Get(ctx, name, metav1.GetOptions{})
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
		_, err = model.Clientset.CoreV1().ConfigMaps(model.Namespace).Update(ctx, existing, metav1.UpdateOptions{})
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
