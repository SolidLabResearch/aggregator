package main

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func getClientCredentials(aggregatorID string) (string, string, error) {
	secret, err := Clientset.CoreV1().Secrets(Namespace).Get(
		context.Background(),
		fmt.Sprintf("client-%s", aggregatorID), metav1.GetOptions{},
	)
	if err != nil {
		return "", "", fmt.Errorf("get client secret: %w", err)
	}

	clientIDBytes, ok := secret.Data["client_id"]
	if !ok {
		return "", "", fmt.Errorf("client_id not found in secret")
	}
	clientSecretBytes, ok := secret.Data["client_secret"]
	if !ok {
		return "", "", fmt.Errorf("client_secret not found in secret")
	}

	return string(clientIDBytes), string(clientSecretBytes), nil
}
