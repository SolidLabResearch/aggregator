package services

import (
	"aggregator/model"
	"context"
	"testing"

	"github.com/maartyman/rdfgo"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

func TestDeployAggregatorServiceCreatesNativeResources(t *testing.T) {
	oldClient, oldNamespace, oldID, oldOwner := model.Clientset, model.Namespace, model.ID, model.Owner
	model.Clientset = fake.NewSimpleClientset()
	model.Namespace, model.ID = "test", "aggregator-1"
	model.Owner = model.User{}
	t.Cleanup(func() {
		model.Clientset, model.Namespace, model.ID, model.Owner = oldClient, oldNamespace, oldID, oldOwner
	})

	predicate := "https://aggregator.example/deployments/fetch#url"
	service := &model.Service{
		KubernetesName: "service-123e4567-e89b-12d3-a456-426614174000",
		InstanceID:     "services-fetch-1",
		Deployment: &model.DeploymentRequest{
			Bindings: map[string]rdfgo.ITerm{predicate: rdfgo.NewNamedNode("https://example.org/data")},
			Definition: &model.ResolvedDeployment{
				Resources: []model.ResolvedResource{
					{ID: "settings", Kind: "ConfigMap", Manifest: runtime.RawExtension{Raw: []byte(`{"apiVersion":"v1","kind":"ConfigMap","data":{"mode":"test"}}`)}},
					{ID: "data", Kind: "PersistentVolumeClaim", Manifest: runtime.RawExtension{Raw: []byte(`{"apiVersion":"v1","kind":"PersistentVolumeClaim","spec":{"accessModes":["ReadWriteOnce"],"resources":{"requests":{"storage":"1Mi"}}}}`)}},
					{ID: "workload", Kind: "Deployment", Manifest: runtime.RawExtension{Raw: []byte(`{
              "apiVersion":"apps/v1","kind":"Deployment",
              "spec":{"selector":{"matchLabels":{"app":"fetch"}},"template":{"metadata":{"labels":{"app":"fetch"}},"spec":{
                "volumes":[{"name":"settings","configMap":{"name":"settings"}},{"name":"data","persistentVolumeClaim":{"claimName":"data"}}],
                "containers":[{"name":"fetch","image":"fetch","ports":[{"name":"http","containerPort":8080}]}]
              }}}
            }`)}},
				},
				InputBindings: []model.ResolvedInputBinding{{Parameter: "url", Predicate: predicate, Targets: []model.ResolvedEnvironmentTarget{{Resource: "workload", Container: "fetch", Env: "GET_URL"}}}},
				Datasets: map[string]model.ResolvedDataset{"content": {Distributions: map[string]model.ResolvedDistribution{
					"content": {Path: "/content", URLType: "accessURL", Target: model.ResolvedRouteTarget{Resource: "workload", Container: "fetch", PortName: "http", Port: 8080}},
				}}},
			},
		},
	}
	if err := DeployAggregatorService(service); err != nil {
		t.Fatalf("DeployAggregatorService: %v", err)
	}

	ctx := context.Background()
	workloadName := ResourceKubernetesName(service.KubernetesName, "workload")
	deployment, err := model.Clientset.AppsV1().Deployments(model.Namespace).Get(ctx, workloadName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get Deployment: %v", err)
	}
	pod := deployment.Spec.Template.Spec
	if pod.Containers[0].Env[0].Value != "https://example.org/data" {
		t.Fatalf("input binding not applied: %#v", pod.Containers[0].Env)
	}
	if pod.Volumes[0].ConfigMap.Name != ResourceKubernetesName(service.KubernetesName, "settings") ||
		pod.Volumes[1].PersistentVolumeClaim.ClaimName != ResourceKubernetesName(service.KubernetesName, "data") {
		t.Fatalf("resource references not resolved: %#v", pod.Volumes)
	}
	if _, err := model.Clientset.CoreV1().Services(model.Namespace).Get(ctx, workloadName, metav1.GetOptions{}); err != nil {
		t.Fatalf("get routed Service: %v", err)
	}
	if err := service.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	deployments, _ := model.Clientset.AppsV1().Deployments(model.Namespace).List(ctx, metav1.ListOptions{})
	services, _ := model.Clientset.CoreV1().Services(model.Namespace).List(ctx, metav1.ListOptions{})
	configMaps, _ := model.Clientset.CoreV1().ConfigMaps(model.Namespace).List(ctx, metav1.ListOptions{})
	claims, _ := model.Clientset.CoreV1().PersistentVolumeClaims(model.Namespace).List(ctx, metav1.ListOptions{})
	if len(deployments.Items)+len(services.Items)+len(configMaps.Items)+len(claims.Items) != 0 {
		t.Fatalf("resources remained after Stop: deployments=%d services=%d configMaps=%d claims=%d",
			len(deployments.Items), len(services.Items), len(configMaps.Items), len(claims.Items))
	}
}
