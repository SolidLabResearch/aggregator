package services

import (
	"aggregator/model"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/maartyman/rdfgo"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNewKubernetesName(t *testing.T) {
	first := NewKubernetesName()
	second := NewKubernetesName()

	if first == second {
		t.Fatalf("generated duplicate Kubernetes names: %q", first)
	}
	if len(first) > 63 {
		t.Fatalf("Kubernetes name has %d characters, want at most 63", len(first))
	}
	if !strings.HasPrefix(first, kubernetesServiceNamePrefix) {
		t.Fatalf("Kubernetes name %q is missing prefix %q", first, kubernetesServiceNamePrefix)
	}
	if _, err := uuid.Parse(strings.TrimPrefix(first, kubernetesServiceNamePrefix)); err != nil {
		t.Fatalf("Kubernetes name %q does not contain a valid UUID: %v", first, err)
	}
}

func TestInjectName(t *testing.T) {
	deployment := &appsv1.Deployment{}
	tests := []struct {
		name string
		obj  interface{}
		got  func() string
	}{
		{"Deployment", deployment, func() string { return deployment.Name }},
	}

	const name = "service-123e4567-e89b-12d3-a456-426614174000"
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := injectName(test.obj, name); err != nil {
				t.Fatalf("injectName() returned error: %v", err)
			}
			if got := test.got(); got != name {
				t.Fatalf("resource name = %q, want %q", got, name)
			}
		})
	}
}

func TestInjectNameRejectsEmptyName(t *testing.T) {
	if err := injectName(&appsv1.Deployment{}, ""); err == nil {
		t.Fatal("injectName() accepted an empty name")
	}
}

func TestResourceKubernetesNameIsStableAndBounded(t *testing.T) {
	service := NewKubernetesName()
	resourceID := strings.Repeat("long-resource-", 8)
	first := ResourceKubernetesName(service, resourceID)
	second := ResourceKubernetesName(service, resourceID)
	if first != second || len(first) > 63 {
		t.Fatalf("invalid generated resource name %q", first)
	}
}

func TestApplyResolvedInputBindingsSetsTargetEnvironment(t *testing.T) {
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "fetch"},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "fetch"}},
		}}},
	}
	predicate := "https://aggregator.example/deployments/fetch#url"
	bindings := []model.ResolvedInputBinding{{
		Parameter: "url", Predicate: predicate,
		Targets: []model.ResolvedEnvironmentTarget{{Resource: "workload", Container: "fetch", Env: "GET_URL"}},
	}}
	values := map[string]rdfgo.ITerm{predicate: rdfgo.NewNamedNode("https://example.org/data")}
	if err := applyResolvedInputBindings(deployment, "workload", bindings, values); err != nil {
		t.Fatalf("applyResolvedInputBindings: %v", err)
	}
	if got := deployment.Spec.Template.Spec.Containers[0].Env; len(got) != 1 || got[0].Name != "GET_URL" || got[0].Value != "https://example.org/data" {
		t.Fatalf("unexpected environment: %#v", got)
	}
}

func TestApplyResolvedInputBindingsTemplatesTargetEnvironment(t *testing.T) {
	deployment := &appsv1.Deployment{Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
		Containers: []corev1.Container{{Name: "pacsoi"}},
	}}}}
	predicate := "https://aggregator.example/deployments/pacsoi#id"
	bindings := []model.ResolvedInputBinding{{
		Parameter: "id", Predicate: predicate,
		Targets: []model.ResolvedEnvironmentTarget{{
			Resource: "workload", Container: "pacsoi", Env: "SOURCES",
			ValueTemplate: "https://pacsoi-kvasir.faqir.org/faqir-management/slices/{{value}}-ActivePatients/query",
		}},
	}}
	values := map[string]rdfgo.ITerm{predicate: rdfgo.NewLiteral("hospital-1", "", nil)}
	if err := applyResolvedInputBindings(deployment, "workload", bindings, values); err != nil {
		t.Fatalf("applyResolvedInputBindings: %v", err)
	}
	want := "https://pacsoi-kvasir.faqir.org/faqir-management/slices/hospital-1-ActivePatients/query"
	if got := deployment.Spec.Template.Spec.Containers[0].Env; len(got) != 1 || got[0].Name != "SOURCES" || got[0].Value != want {
		t.Fatalf("unexpected environment: %#v", got)
	}
}

func TestApplyResolvedInputBindingsSetsMissingValueToEmptyString(t *testing.T) {
	deployment := &appsv1.Deployment{
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "prepare-data",
				Env:  []corev1.EnvVar{{Name: "POLL_INTERVAL", Value: "existing-default"}},
			}},
		}}},
	}
	bindings := []model.ResolvedInputBinding{{
		Parameter: "pollInterval",
		Predicate: "https://aggregator.example/deployments/prepare-data#poll-interval",
		Targets: []model.ResolvedEnvironmentTarget{{
			Resource: "workload", Container: "prepare-data", Env: "POLL_INTERVAL",
		}},
	}}

	if err := applyResolvedInputBindings(deployment, "workload", bindings, map[string]rdfgo.ITerm{}); err != nil {
		t.Fatalf("applyResolvedInputBindings: %v", err)
	}
	if got := deployment.Spec.Template.Spec.Containers[0].Env; len(got) != 1 || got[0].Name != "POLL_INTERVAL" || got[0].Value != "" {
		t.Fatalf("unexpected environment: %#v", got)
	}
}

func TestBuildUMAEnvUsesDedicatedProxyVariable(t *testing.T) {
	oldID, oldNamespace := model.ID, model.Namespace
	model.ID, model.Namespace = "aggregator-1", "test"
	t.Cleanup(func() { model.ID, model.Namespace = oldID, oldNamespace })

	env := buildUMAEnv()
	if len(env) != 1 || env[0].Name != "EGRESS_UMA_URL" || env[0].Value != "http://egress-uma-aggregator-1.test.svc.cluster.local:8080" {
		t.Fatalf("unexpected UMA environment: %#v", env)
	}
}

func TestInjectPublicServiceURLIntoEveryContainer(t *testing.T) {
	deployment := &appsv1.Deployment{Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
		Containers: []corev1.Container{
			{Name: "first", Env: []corev1.EnvVar{{Name: "AGG_PUBLIC_URL", Value: "https://wrong.example"}}},
			{Name: "second"},
		},
	}}}}
	const publicURL = "https://aggregator.example/owner/services/training"
	if err := injectPublicServiceURL(deployment, publicURL); err != nil {
		t.Fatalf("injectPublicServiceURL: %v", err)
	}
	for _, container := range deployment.Spec.Template.Spec.Containers {
		found := false
		for _, env := range container.Env {
			if env.Name == "AGG_PUBLIC_URL" {
				found = true
				if env.Value != publicURL {
					t.Fatalf("container %q has AGG_PUBLIC_URL %q", container.Name, env.Value)
				}
			}
		}
		if !found {
			t.Fatalf("container %q has no AGG_PUBLIC_URL", container.Name)
		}
	}
}

func TestResolveResourceReferences(t *testing.T) {
	deployment := &appsv1.Deployment{Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
		Volumes: []corev1.Volume{
			{Name: "settings", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "settings"}}}},
			{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "data"}}},
		},
		Containers: []corev1.Container{{Name: "app", EnvFrom: []corev1.EnvFromSource{{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "settings"}}}}}},
	}}}}
	resolveResourceReferences(deployment, map[string]string{"settings": "generated-settings", "data": "generated-data"})
	if deployment.Spec.Template.Spec.Volumes[0].ConfigMap.Name != "generated-settings" ||
		deployment.Spec.Template.Spec.Volumes[1].PersistentVolumeClaim.ClaimName != "generated-data" ||
		deployment.Spec.Template.Spec.Containers[0].EnvFrom[0].ConfigMapRef.Name != "generated-settings" {
		t.Fatalf("resource references were not resolved: %#v", deployment.Spec.Template.Spec)
	}
}
