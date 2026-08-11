package services

import (
	"aggregator/model"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/maartyman/rdfgo"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const kubernetesServiceNamePrefix = "service-"

func NewKubernetesName() string {
	return kubernetesServiceNamePrefix + uuid.NewString()
}

func ResourceKubernetesName(serviceName, resourceID string) string {
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(resourceID)))[:6]
	available := 63 - len(serviceName) - len(hash) - 2
	if available < 1 {
		available = 1
	}
	part := strings.Trim(resourceID, "-")
	if len(part) > available {
		part = strings.TrimRight(part[:available], "-")
	}
	if part == "" {
		part = "r"
	}
	return serviceName + "-" + part + "-" + hash
}

func decodeK8sObject(
	kind string,
	raw []byte,
) (interface{}, error) {

	switch kind {

	case "Deployment":
		var d appsv1.Deployment
		if err := json.Unmarshal(raw, &d); err != nil {
			return nil, err
		}
		return &d, nil

	case "ConfigMap":
		var configMap corev1.ConfigMap
		if err := json.Unmarshal(raw, &configMap); err != nil {
			return nil, err
		}
		return &configMap, nil

	case "PersistentVolumeClaim":
		var claim corev1.PersistentVolumeClaim
		if err := json.Unmarshal(raw, &claim); err != nil {
			return nil, err
		}
		return &claim, nil

	default:
		return nil, fmt.Errorf("unsupported orchestration type")
	}
}

func applyResolvedInputBindings(obj interface{}, resourceID string, bindings []model.ResolvedInputBinding, values map[string]rdfgo.ITerm) error {
	for _, binding := range bindings {
		term, ok := values[binding.Predicate]
		value := ""
		if ok {
			value = strings.Trim(term.GetValue(), "<>")
		}
		for _, target := range binding.Targets {
			if target.Resource != resourceID {
				continue
			}
			targetValue := value
			if target.ValueTemplate != "" {
				targetValue = strings.ReplaceAll(target.ValueTemplate, "{{value}}", value)
			}
			deployment, ok := obj.(*appsv1.Deployment)
			if !ok {
				return fmt.Errorf("input %q environment target %q is not a Deployment", binding.Parameter, resourceID)
			}
			found := false
			for index := range deployment.Spec.Template.Spec.Containers {
				container := &deployment.Spec.Template.Spec.Containers[index]
				if container.Name != target.Container {
					continue
				}
				found = true
				setEnvironmentVariable(container, target.Env, targetValue)
			}
			if !found {
				return fmt.Errorf("input %q references unknown container %q", binding.Parameter, target.Container)
			}
		}
	}
	return nil
}

func setEnvironmentVariable(container *corev1.Container, name, value string) {
	for index := range container.Env {
		if container.Env[index].Name == name {
			container.Env[index].Value = value
			container.Env[index].ValueFrom = nil
			return
		}
	}
	container.Env = append(container.Env, corev1.EnvVar{Name: name, Value: value})
}

// resolveResourceReferences treats local resource IDs in well-known PodSpec
// reference fields as symbolic names and replaces them with generated names.
func resolveResourceReferences(obj interface{}, names map[string]string) {
	deployment, ok := obj.(*appsv1.Deployment)
	if !ok {
		return
	}
	pod := &deployment.Spec.Template.Spec
	for index := range pod.Volumes {
		volume := &pod.Volumes[index]
		if volume.ConfigMap != nil {
			volume.ConfigMap.Name = resolvedResourceName(volume.ConfigMap.Name, names)
		}
		if volume.PersistentVolumeClaim != nil {
			volume.PersistentVolumeClaim.ClaimName = resolvedResourceName(volume.PersistentVolumeClaim.ClaimName, names)
		}
	}
	for index := range pod.Containers {
		container := &pod.Containers[index]
		for envIndex := range container.EnvFrom {
			if container.EnvFrom[envIndex].ConfigMapRef != nil {
				container.EnvFrom[envIndex].ConfigMapRef.Name = resolvedResourceName(container.EnvFrom[envIndex].ConfigMapRef.Name, names)
			}
		}
		for envIndex := range container.Env {
			valueFrom := container.Env[envIndex].ValueFrom
			if valueFrom != nil && valueFrom.ConfigMapKeyRef != nil {
				valueFrom.ConfigMapKeyRef.Name = resolvedResourceName(valueFrom.ConfigMapKeyRef.Name, names)
			}
		}
	}
}

func resolvedResourceName(value string, names map[string]string) string {
	if resolved, ok := names[value]; ok {
		return resolved
	}
	return value
}

func applyObject(ctx context.Context, obj interface{}) error {

	switch r := obj.(type) {

	case *appsv1.Deployment:
		_, err := model.Clientset.AppsV1().
			Deployments(r.Namespace).
			Create(ctx, r, metav1.CreateOptions{})
		return err

	case *corev1.ConfigMap:
		_, err := model.Clientset.CoreV1().ConfigMaps(r.Namespace).Create(ctx, r, metav1.CreateOptions{})
		return err

	case *corev1.PersistentVolumeClaim:
		_, err := model.Clientset.CoreV1().PersistentVolumeClaims(r.Namespace).Create(ctx, r, metav1.CreateOptions{})
		return err

	default:
		return fmt.Errorf("unsupported object type")
	}
}

func buildUMAEnv() []corev1.EnvVar {
	proxy := fmt.Sprintf(
		"http://egress-uma-%s.%s.svc.cluster.local:8080",
		model.ID,
		model.Namespace,
	)

	return []corev1.EnvVar{
		{Name: "EGRESS_UMA_URL", Value: proxy},
	}
}

func injectUMAEnv(obj interface{}) error {
	envVars := buildUMAEnv()

	switch r := obj.(type) {

	case *appsv1.Deployment:
		injectIntoPodSpec(&r.Spec.Template.Spec, envVars)

	case *corev1.ConfigMap, *corev1.PersistentVolumeClaim:
		return nil
	default:
		return fmt.Errorf("unsupported object type for UMA injection")
	}

	return nil
}

func injectIntoPodSpec(podSpec *corev1.PodSpec, envVars []corev1.EnvVar) {
	for i := range podSpec.Containers {
		podSpec.Containers[i].Env = append(
			podSpec.Containers[i].Env,
			envVars...,
		)
	}
}

func injectNamespace(obj interface{}, namespace string) error {
	switch r := obj.(type) {
	case *appsv1.Deployment:
		r.Namespace = namespace
	case *corev1.ConfigMap:
		r.Namespace = namespace
	case *corev1.PersistentVolumeClaim:
		r.Namespace = namespace
	default:
		return fmt.Errorf("unsupported object type")
	}
	return nil
}

func injectName(obj interface{}, name string) error {
	if name == "" {
		return fmt.Errorf("kubernetes resource name is required")
	}

	switch r := obj.(type) {
	case *appsv1.Deployment:
		r.Name = name
	case *corev1.ConfigMap:
		r.Name = name
	case *corev1.PersistentVolumeClaim:
		r.Name = name
	default:
		return fmt.Errorf("unsupported object type")
	}
	return nil
}

func injectLabels(obj interface{}, service *model.Service, resourceID string) error {

	labels := map[string]string{
		"app.kubernetes.io/name":               "aggregator-service",
		"app.kubernetes.io/part-of":            "aggregator-platform",
		"app.kubernetes.io/managed-by":         "aggregator-instance",
		"agg.knows.idlab.ugent.be/managed-by":  model.ID,
		"agg.knows.idlab.ugent.be/id":          service.InstanceID,
		"agg.knows.idlab.ugent.be/resource-id": resourceID,
	}

	switch r := obj.(type) {

	case *appsv1.Deployment:
		mergeLabels(&r.ObjectMeta, labels)
		mergeLabels(&r.Spec.Template.ObjectMeta, labels)

	case *corev1.ConfigMap:
		mergeLabels(&r.ObjectMeta, labels)

	case *corev1.PersistentVolumeClaim:
		mergeLabels(&r.ObjectMeta, labels)

	default:
		return fmt.Errorf("unsupported object for label injection")
	}

	return nil
}

func orderedResources(resources []model.ResolvedResource) []model.ResolvedResource {
	result := append([]model.ResolvedResource(nil), resources...)
	priority := func(kind string) int {
		switch kind {
		case "ConfigMap":
			return 0
		case "PersistentVolumeClaim":
			return 1
		default:
			return 2
		}
	}
	sort.SliceStable(result, func(i, j int) bool { return priority(result[i].Kind) < priority(result[j].Kind) })
	return result
}

func mergeLabels(meta *metav1.ObjectMeta, labels map[string]string) {
	if meta.Labels == nil {
		meta.Labels = map[string]string{}
	}
	for k, v := range labels {
		meta.Labels[k] = v
	}
}

func extractServicePortsByResource(definition *model.ResolvedDeployment) map[string][]int32 {
	portSets := map[string]map[int32]struct{}{}

	for _, dataset := range definition.Datasets {
		for _, distribution := range dataset.Distributions {
			port := int32(distribution.Target.Port)
			if port > 0 {
				if portSets[distribution.Target.Resource] == nil {
					portSets[distribution.Target.Resource] = map[int32]struct{}{}
				}
				portSets[distribution.Target.Resource][port] = struct{}{}
			}
		}
	}
	for _, endpoint := range definition.Endpoints {
		port := int32(endpoint.Target.Port)
		if port > 0 {
			if portSets[endpoint.Target.Resource] == nil {
				portSets[endpoint.Target.Resource] = map[int32]struct{}{}
			}
			portSets[endpoint.Target.Resource][port] = struct{}{}
		}
	}
	result := map[string][]int32{}
	for resourceID, portSet := range portSets {
		for port := range portSet {
			result[resourceID] = append(result[resourceID], port)
		}
		sort.Slice(result[resourceID], func(i, j int) bool { return result[resourceID][i] < result[resourceID][j] })
	}
	return result
}

func buildServicePorts(ports []int32) []corev1.ServicePort {
	servicePorts := make([]corev1.ServicePort, 0, len(ports))

	for _, port := range ports {
		servicePorts = append(servicePorts, corev1.ServicePort{
			Name:       fmt.Sprintf("port-%d", port),
			Port:       port,
			TargetPort: intstr.FromInt32(port),
			Protocol:   corev1.ProtocolTCP,
		})
	}

	return servicePorts
}
