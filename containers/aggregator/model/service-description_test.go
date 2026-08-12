package model

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestServiceDescriptionUsesResolvedProfileAndAllDistributions(t *testing.T) {
	oldClient, oldID, oldNamespace := Clientset, ID, Namespace
	ID, Namespace = "aggregator-1", "test"
	labels := map[string]string{
		"app.kubernetes.io/name":              "aggregator-service",
		"agg.knows.idlab.ugent.be/managed-by": ID,
		"agg.knows.idlab.ugent.be/id":         "services-fetch-1",
	}
	Clientset = fake.NewSimpleClientset(
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "fetch-workload", Namespace: Namespace, Labels: labels}},
		&corev1.Endpoints{ObjectMeta: metav1.ObjectMeta{Name: "fetch-workload", Namespace: Namespace}, Subsets: []corev1.EndpointSubset{{Addresses: []corev1.EndpointAddress{{IP: "10.0.0.1"}}}}},
	)
	t.Cleanup(func() { Clientset, ID, Namespace = oldClient, oldID, oldNamespace })

	profileURI := "https://aggregator.example/profiles/fetch"
	service := &Service{
		InstanceID: "services-fetch-1", FullPath: "https://aggregator.example/aggregator-1/services/fetch-1", CreatedAt: time.Now(),
		Deployment: &DeploymentRequest{Definition: &ResolvedDeployment{
			URI: "https://aggregator.example/deployments/fetch", ProfileURI: profileURI,
			Prefixes:       map[string]string{"dct": "http://purl.org/dc/terms/"},
			ServiceProfile: &ResolvedServiceProfile{Title: "Fetch service", AccessRoles: map[string]ResolvedAccessRole{"reader": {URI: profileURI + "#role-reader"}}},
			Endpoints:      map[string]ResolvedEndpoint{"refresh": {Path: "/refresh"}},
			Datasets: map[string]ResolvedDataset{"content": {
				ProfileURI: profileURI + "#dataset-content",
				Distributions: map[string]ResolvedDistribution{
					"raw":  {Path: "/raw", URLType: "accessURL"},
					"file": {Path: "/file", URLType: "downloadURL"},
				},
			}},
		}},
	}
	if err := service.InitDescription(); err != nil {
		t.Fatalf("InitDescription: %v", err)
	}
	representation, err := service.Description.FnORepresentation()
	if err != nil {
		t.Fatalf("FnORepresentation: %v", err)
	}
	text := string(representation)
	for _, expected := range []string{profileURI, profileURI + "#dataset-content", profileURI + "#role-reader", "/refresh", "/raw", "/file"} {
		if !strings.Contains(text, expected) {
			t.Errorf("service description does not contain %q:\n%s", expected, text)
		}
	}
}
