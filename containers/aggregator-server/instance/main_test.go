package instance

import (
	"context"
	"fmt"
	"testing"

	"aggregator/model"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestDeployAggregatorRollsBackPartialResources(t *testing.T) {
	ctx := context.Background()
	const aggregatorID = "failed-aggregator"
	labels := map[string]string{"agg.knows.idlab.ugent.be/managed-by": aggregatorID}
	client := fake.NewSimpleClientset(
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "egress-uma-" + aggregatorID, Namespace: "test-ns", Labels: labels}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "egress-uma-" + aggregatorID, Namespace: "test-ns", Labels: labels}},
	)

	originalClientset, originalNamespace := model.Clientset, model.Namespace
	model.Clientset, model.Namespace = client, "test-ns"
	t.Cleanup(func() { model.Clientset, model.Namespace = originalClientset, originalNamespace })

	client.Fake.PrependReactor("create", "rolebindings", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("role binding denied")
	})

	if err := DeployAggregator("owner", aggregatorID, "", ctx); err == nil {
		t.Fatal("expected deployment to fail")
	}
	if _, err := client.AppsV1().Deployments("test-ns").Get(ctx, "egress-uma-"+aggregatorID, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("expected partial egress deployment to be removed, got %v", err)
	}
	if _, err := client.CoreV1().Services("test-ns").Get(ctx, "egress-uma-"+aggregatorID, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("expected partial egress service to be removed, got %v", err)
	}
	if _, err := client.CoreV1().ServiceAccounts("test-ns").Get(ctx, "sa-"+aggregatorID, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("expected partial service account to be removed, got %v", err)
	}
}

func TestEnsureConfigMap_RetriesOnConflict(t *testing.T) {
	ctx := context.Background()
	const configMapName = "egress-uma-config-test-ns"
	client := fake.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      configMapName,
			Namespace: "test-ns",
		},
		Data: map[string]string{
			"tokens.json": `{"access_token":"old"}`,
		},
	})

	original := model.Clientset
	originalNamespace := model.Namespace
	model.Clientset = client
	model.Namespace = "test-ns"
	t.Cleanup(func() {
		model.Clientset = original
		model.Namespace = originalNamespace
	})

	updateCalls := 0
	client.Fake.PrependReactor("update", "configmaps", func(action k8stesting.Action) (bool, runtime.Object, error) {
		updateCalls++
		if updateCalls == 1 {
			return true, nil, apierrors.NewConflict(schema.GroupResource{Group: "", Resource: "configmaps"}, configMapName, nil)
		}
		return false, nil, nil
	})

	payload := map[string]string{
		"tokens.json": `{"access_token":"new"}`,
	}

	if _, err := ensureConfigMap("test-ns", "egress-uma-config", payload, ctx); err != nil {
		t.Fatalf("Expected update retry to succeed, got error: %v", err)
	}

	if updateCalls < 2 {
		t.Fatalf("Expected update retry on conflict, got %d update call(s)", updateCalls)
	}

	updated, err := client.CoreV1().ConfigMaps("test-ns").Get(ctx, configMapName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Failed to fetch configmap: %v", err)
	}
	if updated.Data["tokens.json"] != `{"access_token":"new"}` {
		t.Fatalf("ConfigMap not updated after retry, got %q", updated.Data["tokens.json"])
	}
}

func TestResolveOwnerID_EmptyUsesNamespaceFallback(t *testing.T) {
	got := resolveOwnerID("", "ns-test-123")
	if got == "" {
		t.Fatal("Expected non-empty owner WebID fallback for none flow")
	}
}
