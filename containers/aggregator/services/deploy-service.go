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

	app := service.Deployment
	definition := app.Definition
	if definition == nil || len(definition.Resources) == 0 {
		return fmt.Errorf("resolved deployment has no resources")
	}
	resourceNames := map[string]string{}
	for _, resource := range definition.Resources {
		resourceNames[resource.ID] = ResourceKubernetesName(service.KubernetesName, resource.ID)
	}
	for _, resource := range orderedResources(definition.Resources) {
		obj, err := decodeK8sObject(resource.Kind, resource.Manifest.Raw)
		if err != nil {
			return err
		}
		if err := applyResolvedInputBindings(obj, resource.ID, definition.InputBindings, app.Bindings); err != nil {
			return err
		}
		resolveResourceReferences(obj, resourceNames)
		if useUMA {
			if err := injectUMAEnv(obj); err != nil {
				return err
			}
		}
		if err := injectNamespace(obj, model.Namespace); err != nil {
			return err
		}
		if err := injectName(obj, resourceNames[resource.ID]); err != nil {
			return err
		}
		if err := injectLabels(obj, service, resource.ID); err != nil {
			return err
		}
		if finalBytes, err := json.MarshalIndent(obj, "", "  "); err == nil {
			logrus.Debugf("Final %s resource %s for service %s:\n%s", resource.Kind, resource.ID, service.KubernetesName, string(finalBytes))
		}
		if err := applyObject(ctx, obj); err != nil {
			return fmt.Errorf("create resource %q: %w", resource.ID, err)
		}
	}

	logrus.Infof("Service %s deployed successfully", service.KubernetesName)
	return nil
}

func expose(service *model.Service, ctx context.Context) error {
	portsByResource := extractServicePortsByResource(service.Deployment.Definition)
	if len(portsByResource) == 0 {
		return fmt.Errorf("no distribution ports defined for service %s", service.KubernetesName)
	}
	for resourceID, ports := range portsByResource {
		name := ResourceKubernetesName(service.KubernetesName, resourceID)
		if _, err := model.Clientset.CoreV1().Services(model.Namespace).Get(ctx, name, metav1.GetOptions{}); err == nil {
			return fmt.Errorf("service %s already exists", name)
		}
		labels := map[string]string{
			"app.kubernetes.io/name":               "aggregator-service",
			"app.kubernetes.io/managed-by":         "aggregator-instance",
			"agg.knows.idlab.ugent.be/managed-by":  model.ID,
			"agg.knows.idlab.ugent.be/id":          service.InstanceID,
			"agg.knows.idlab.ugent.be/resource-id": resourceID,
		}
		svcSpec := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: model.Namespace, Labels: labels},
			Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, Selector: map[string]string{
				"app.kubernetes.io/name":               "aggregator-service",
				"agg.knows.idlab.ugent.be/managed-by":  model.ID,
				"agg.knows.idlab.ugent.be/id":          service.InstanceID,
				"agg.knows.idlab.ugent.be/resource-id": resourceID,
			}, Ports: buildServicePorts(ports)},
		}
		if _, err := model.Clientset.CoreV1().Services(model.Namespace).Create(ctx, svcSpec, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("failed to create service for resource %q: %w", resourceID, err)
		}
		logrus.Infof("Service %s created for resource %s with ports %v", name, resourceID, ports)
	}
	return nil
}
