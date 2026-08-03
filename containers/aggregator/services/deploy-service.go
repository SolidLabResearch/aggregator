package services

import (
	"aggregator/model"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func DeployAggregatorService(
	service *model.Service,
) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	useUMA := strings.TrimSpace(model.Owner.AuthzServerURL) != ""

	// Clean up if anything fails
	cleanup := func() {
		if err := service.Stop(); err != nil {
			logrus.WithError(err).Warn("Failed to clean up service resources")
		}
	}

	// deploy the service orchestration
	if err := deploy(service, useUMA, ctx); err != nil {
		cleanup()
		return fmt.Errorf("deployment creation failed: %w", err)
	}

	// expose outputs with service
	if err := expose(service, ctx); err != nil {
		cleanup()
		return fmt.Errorf("service creation failed: %w", err)
	}

	// creation successful
	return nil
}

func deploy(
	service *model.Service,
	useUMA bool,
	ctx context.Context,
) error {

	sc := service.Configuration
	app := service.Deployment

	// Build substitution values
	values, err := buildSubstitutionMap(
		sc,
		app,
	)
	if err != nil {
		return err
	}

	// Substitute into orchestration spec
	raw, err := substituteOrchestration(sc, values)
	if err != nil {
		return err
	}

	// Decode into K8s object
	obj, err := decodeK8sObject(sc, raw)
	if err != nil {
		return err
	}

	// Inject UMA Proxy envs
	if useUMA {
		err = injectUMAEnv(obj)
		if err != nil {
			return err
		}
	}

	// Inject namespace
	err = injectNamespace(obj, model.Namespace)
	if err != nil {
		return err
	}

	// The requested service ID is an external path identifier. Kubernetes
	// resources use a separate, internal name to avoid collisions and DNS
	// label length constraints.
	err = injectName(obj, service.KubernetesName)
	if err != nil {
		return err
	}

	// Inject labels
	err = injectLabels(obj, service)
	if err != nil {
		return err
	}

	// Log final spec
	if finalBytes, err := json.MarshalIndent(obj, "", "  "); err == nil {
		logrus.Debugf("Final deployment spec for service %s:\n%s", service.KubernetesName, string(finalBytes))
	}

	// Apply
	err = applyObject(ctx, obj)
	if err != nil {
		return err
	}

	logrus.Infof("Service %s deployed successfully", service.KubernetesName)
	return nil
}

func expose(service *model.Service, ctx context.Context) error {

	// Check if service already exists
	_, err := model.Clientset.CoreV1().
		Services(model.Namespace).
		Get(ctx, service.KubernetesName, metav1.GetOptions{})

	if err == nil {
		return fmt.Errorf("service %s already exists", service.KubernetesName)
	}

	sc := service.Configuration

	// Extract ports used by exposed dataset distributions.
	ports := extractServicePorts(sc)

	if len(ports) == 0 {
		return fmt.Errorf("no distribution ports defined for service %s", service.KubernetesName)
	}

	// ✅ Build k8s ports
	servicePorts := buildServicePorts(ports)

	// ✅ Labels (same as deployment, important!)
	labels := map[string]string{
		"app.kubernetes.io/name":              "aggregator-service",
		"app.kubernetes.io/managed-by":        "aggregator-instance",
		"agg.knows.idlab.ugent.be/managed-by": model.ID,
		"agg.knows.idlab.ugent.be/id":         service.InstanceID,
	}

	// ✅ Create Service spec
	svcSpec := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      service.KubernetesName,
			Namespace: model.Namespace,
			Labels:    labels,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Selector: map[string]string{
				"app.kubernetes.io/name":              "aggregator-service",
				"agg.knows.idlab.ugent.be/managed-by": model.ID,
				"agg.knows.idlab.ugent.be/id":         service.InstanceID,
			},
			Ports: servicePorts,
		},
	}

	// ✅ Create Service
	_, err = model.Clientset.CoreV1().
		Services(model.Namespace).
		Create(ctx, svcSpec, metav1.CreateOptions{})

	if err != nil {
		return fmt.Errorf("failed to create service: %w", err)
	}

	logrus.Infof("Service %s created with ports %v", service.KubernetesName, ports)

	return nil
}
