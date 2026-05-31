package services

import (
	"aggregator/model"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func buildSubstitutionMap(
	sc *model.ServiceConfiguration,
	app *model.Application,
) (map[string]string, error) {

	values := make(map[string]string)

	for predicateURI, input := range sc.Spec.InputMapping {

		term, ok := app.Bindings[predicateURI]
		if !ok {
			return nil, fmt.Errorf("missing binding for predicate: %s", predicateURI)
		}

		// extract value from RDF term
		val := strings.Trim(term.GetValue(), "<>")

		values[input.ID] = val
	}

	return values, nil
}

func substituteOrchestration(
	sc *model.ServiceConfiguration,
	values map[string]string,
) ([]byte, error) {

	raw := sc.Spec.ServiceMapping.Orchestration.Spec.Raw

	result := string(raw)

	for id, val := range values {
		placeholder := "$(" + id + ")"
		result = strings.ReplaceAll(result, placeholder, val)
	}

	// safety check
	if strings.Contains(result, "$(") {
		return nil, fmt.Errorf("unresolved placeholders remain in orchestration spec")
	}

	return []byte(result), nil
}

func decodeK8sObject(
	sc *model.ServiceConfiguration,
	raw []byte,
) (interface{}, error) {

	switch sc.Spec.ServiceMapping.Orchestration.Type {

	case "Deployment":
		var d appsv1.Deployment
		if err := json.Unmarshal(raw, &d); err != nil {
			return nil, err
		}
		return &d, nil

	case "Job":
		var j batchv1.Job
		if err := json.Unmarshal(raw, &j); err != nil {
			return nil, err
		}
		return &j, nil

	case "CronJob":
		var cj batchv1.CronJob
		if err := json.Unmarshal(raw, &cj); err != nil {
			return nil, err
		}
		return &cj, nil

	default:
		return nil, fmt.Errorf("unsupported orchestration type")
	}
}

func applyObject(ctx context.Context, obj interface{}) error {

	switch r := obj.(type) {

	case *appsv1.Deployment:
		_, err := model.Clientset.AppsV1().
			Deployments(r.Namespace).
			Create(ctx, r, metav1.CreateOptions{})
		return err

	case *batchv1.Job:
		_, err := model.Clientset.BatchV1().
			Jobs(r.Namespace).
			Create(ctx, r, metav1.CreateOptions{})
		return err

	case *batchv1.CronJob:
		_, err := model.Clientset.BatchV1().
			CronJobs(r.Namespace).
			Create(ctx, r, metav1.CreateOptions{})
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
		{Name: "HTTP_PROXY", Value: proxy},
		{Name: "http_proxy", Value: proxy},
	}
}

func injectUMAEnv(obj interface{}) error {
	envVars := buildUMAEnv()

	switch r := obj.(type) {

	case *appsv1.Deployment:
		injectIntoPodSpec(&r.Spec.Template.Spec, envVars)

	case *batchv1.Job:
		injectIntoPodSpec(&r.Spec.Template.Spec, envVars)

	case *batchv1.CronJob:
		injectIntoPodSpec(&r.Spec.JobTemplate.Spec.Template.Spec, envVars)

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
	case *batchv1.Job:
		r.Namespace = namespace
	case *batchv1.CronJob:
		r.Namespace = namespace
	default:
		return fmt.Errorf("unsupported object type")
	}
	return nil
}

func injectLabels(obj interface{}, service *model.Service) error {

	labels := map[string]string{
		"app.kubernetes.io/name":              "aggregator-service",
		"app.kubernetes.io/part-of":           "aggregator-platform",
		"app.kubernetes.io/managed-by":        "aggregator-instance",
		"agg.knows.idlab.ugent.be/managed-by": model.ID,
		"agg.knows.idlab.ugent.be/id":         service.InstanceID,
	}

	switch r := obj.(type) {

	case *appsv1.Deployment:
		mergeLabels(&r.ObjectMeta, labels)
		mergeLabels(&r.Spec.Template.ObjectMeta, labels)

	case *batchv1.Job:
		mergeLabels(&r.ObjectMeta, labels)
		mergeLabels(&r.Spec.Template.ObjectMeta, labels)

	case *batchv1.CronJob:
		mergeLabels(&r.ObjectMeta, labels)
		mergeLabels(&r.Spec.JobTemplate.Spec.Template.ObjectMeta, labels)

	default:
		return fmt.Errorf("unsupported object for label injection")
	}

	return nil
}

func mergeLabels(meta *metav1.ObjectMeta, labels map[string]string) {
	if meta.Labels == nil {
		meta.Labels = map[string]string{}
	}
	for k, v := range labels {
		meta.Labels[k] = v
	}
}

func extractServicePorts(sc *model.ServiceConfiguration) []int32 {
	portSet := make(map[int32]struct{})

	for _, output := range sc.Spec.OutputMapping {
		if output.Distribution != nil &&
			output.Distribution.Access != nil {

			port := int32(output.Distribution.Access.ServicePort)
			if port > 0 {
				portSet[port] = struct{}{}
			}
		}
	}

	// convert to slice
	ports := make([]int32, 0, len(portSet))
	for p := range portSet {
		ports = append(ports, p)
	}

	return ports
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
