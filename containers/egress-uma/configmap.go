package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	instanceConfigMapName = "aggregator-instance-config"
	egressConfigMapName   = "egress-uma-config"
	namespaceFilePath     = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

type configMapWriter struct {
	clientset *kubernetes.Clientset
	namespace string
}

type tokenFilePayload struct {
	AccessToken       string `json:"access_token"`
	RefreshToken      string `json:"refresh_token"`
	AccessTokenExpiry string `json:"access_token_expiry"`
}

var statusWriter *configMapWriter

func initConfigMapWriter() {
	namespace, err := resolveNamespace()
	if err != nil {
		logrus.WithError(err).Warn("Unable to determine namespace for token status updates")
		return
	}

	cfg, err := rest.InClusterConfig()
	if err != nil {
		logrus.WithError(err).Warn("Unable to initialize in-cluster config for token status updates")
		return
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		logrus.WithError(err).Warn("Unable to create Kubernetes client for token status updates")
		return
	}

	statusWriter = &configMapWriter{
		clientset: clientset,
		namespace: namespace,
	}
}

func resolveNamespace() (string, error) {
	if namespace := strings.TrimSpace(os.Getenv("POD_NAMESPACE")); namespace != "" {
		return namespace, nil
	}

	data, err := os.ReadFile(namespaceFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to read namespace file: %w", err)
	}

	namespace := strings.TrimSpace(string(data))
	if namespace == "" {
		return "", fmt.Errorf("namespace file is empty")
	}

	return namespace, nil
}

func updateTokenStatus(expiry time.Time, refreshToken string, accessToken string) {
	if statusWriter == nil {
		return
	}

	expiryValue := ""
	if !expiry.IsZero() {
		expiryValue = expiry.UTC().Format(time.RFC3339)
	}

	if err := statusWriter.upsertConfigMap(instanceConfigMapName, map[string]string{"access_token_expiry": expiryValue}); err != nil {
		logrus.WithError(err).Warn("Failed to update access token expiry")
	}

	payload, err := buildTokenPayload(accessToken, refreshToken, expiryValue)
	if err != nil {
		logrus.WithError(err).Warn("Failed to build token payload")
		return
	}

	if err := statusWriter.upsertConfigMap(egressConfigMapName, map[string]string{"tokens.json": payload}); err != nil {
		logrus.WithError(err).Warn("Failed to update tokens configmap")
	}
}

func markTokenInvalid(err error) {
	if err != nil {
		logrus.WithError(err).Warn("Marking token as invalid")
	}
	TokenMutex.Lock()
	AccessToken = ""
	TokenExpiry = time.Time{}
	refreshToken := RefreshToken
	TokenMutex.Unlock()
	updateTokenStatus(time.Time{}, refreshToken, "")
}

func buildTokenPayload(accessToken string, refreshToken string, expiry string) (string, error) {
	payload := tokenFilePayload{
		AccessToken:       accessToken,
		RefreshToken:      refreshToken,
		AccessTokenExpiry: expiry,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func (w *configMapWriter) upsertConfigMap(name string, data map[string]string) error {
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cm, err := w.clientset.CoreV1().ConfigMaps(w.namespace).Get(ctx, name, metav1.GetOptions{})
		cancel()
		if err != nil {
			if apierrors.IsNotFound(err) {
				ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
				newCM := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      name,
						Namespace: w.namespace,
					},
					Data: data,
				}
				_, createErr := w.clientset.CoreV1().ConfigMaps(w.namespace).Create(ctx, newCM, metav1.CreateOptions{})
				cancel()
				return createErr
			}
			return err
		}

		if cm.Data == nil {
			cm.Data = map[string]string{}
		}
		for key, value := range data {
			cm.Data[key] = value
		}

		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		_, err = w.clientset.CoreV1().ConfigMaps(w.namespace).Update(ctx, cm, metav1.UpdateOptions{})
		cancel()
		if apierrors.IsConflict(err) {
			continue
		}
		return err
	}
}
