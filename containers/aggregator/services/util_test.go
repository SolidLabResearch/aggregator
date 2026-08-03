package services

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
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
	job := &batchv1.Job{}
	cronJob := &batchv1.CronJob{}
	tests := []struct {
		name string
		obj  interface{}
		got  func() string
	}{
		{"Deployment", deployment, func() string { return deployment.Name }},
		{"Job", job, func() string { return job.Name }},
		{"CronJob", cronJob, func() string { return cronJob.Name }},
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
