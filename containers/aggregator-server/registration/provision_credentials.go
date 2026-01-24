package registration

import (
	"aggregator/model"
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	aggregatorConfigNamespace   = "aggregator-app"
	provisionUMASecretName      = "aggregator-provision-uma"
	provisionUMAClientIDKey     = "provision_uma_client_id"
	provisionUMAClientSecretKey = "provision_uma_client_secret"
)

type provisionUMACredentials struct {
	ClientID     string
	ClientSecret string
}

func loadProvisionUMACredentials(ctx context.Context) (provisionUMACredentials, bool, error) {
	if model.Clientset == nil {
		return provisionUMACredentials{}, false, fmt.Errorf("kubernetes client not initialized")
	}

	secret, err := model.Clientset.CoreV1().Secrets(aggregatorConfigNamespace).Get(ctx, provisionUMASecretName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return provisionUMACredentials{}, false, nil
		}
		return provisionUMACredentials{}, false, fmt.Errorf("failed to fetch secret %s: %w", provisionUMASecretName, err)
	}

	if secret.Data == nil {
		return provisionUMACredentials{}, false, nil
	}

	clientID := strings.TrimSpace(string(secret.Data[provisionUMAClientIDKey]))
	clientSecret := strings.TrimSpace(string(secret.Data[provisionUMAClientSecretKey]))
	if clientID == "" || clientSecret == "" {
		return provisionUMACredentials{}, false, nil
	}

	return provisionUMACredentials{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}, true, nil
}

func storeProvisionUMACredentials(ctx context.Context, clientID string, clientSecret string) error {
	if model.Clientset == nil {
		return fmt.Errorf("kubernetes client not initialized")
	}
	if strings.TrimSpace(clientID) == "" || strings.TrimSpace(clientSecret) == "" {
		return fmt.Errorf("client credentials are required")
	}

	secretClient := model.Clientset.CoreV1().Secrets(aggregatorConfigNamespace)
	secret, err := secretClient.Get(ctx, provisionUMASecretName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			secret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      provisionUMASecretName,
					Namespace: aggregatorConfigNamespace,
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					provisionUMAClientIDKey:     []byte(clientID),
					provisionUMAClientSecretKey: []byte(clientSecret),
				},
			}
			if _, err := secretClient.Create(ctx, secret, metav1.CreateOptions{}); err != nil {
				return fmt.Errorf("failed to create secret %s: %w", provisionUMASecretName, err)
			}
			return nil
		}
		return fmt.Errorf("failed to fetch secret %s: %w", provisionUMASecretName, err)
	}

	if secret.Data == nil {
		secret.Data = map[string][]byte{}
	}
	secret.Data[provisionUMAClientIDKey] = []byte(clientID)
	secret.Data[provisionUMAClientSecretKey] = []byte(clientSecret)

	if _, err := secretClient.Update(ctx, secret, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("failed to update secret %s: %w", provisionUMASecretName, err)
	}

	return nil
}
