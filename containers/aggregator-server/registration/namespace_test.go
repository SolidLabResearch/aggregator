package registration

import (
	"context"
	"testing"

	"aggregator/model"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestEnsureConfigMap_RetriesOnConflict(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "egress-uma-config",
			Namespace: "test-ns",
		},
		Data: map[string]string{
			"tokens.json": `{"access_token":"old"}`,
		},
	})

	original := model.Clientset
	model.Clientset = client
	t.Cleanup(func() { model.Clientset = original })

	updateCalls := 0
	client.Fake.PrependReactor("update", "configmaps", func(action k8stesting.Action) (bool, runtime.Object, error) {
		updateCalls++
		if updateCalls == 1 {
			return true, nil, apierrors.NewConflict(schema.GroupResource{Group: "", Resource: "configmaps"}, "egress-uma-config", nil)
		}
		return false, nil, nil
	})

	payload := map[string]string{
		"tokens.json": `{"access_token":"new"}`,
	}

	if err := ensureConfigMap("test-ns", "egress-uma-config", payload, ctx); err != nil {
		t.Fatalf("Expected update retry to succeed, got error: %v", err)
	}

	if updateCalls < 2 {
		t.Fatalf("Expected update retry on conflict, got %d update call(s)", updateCalls)
	}

	updated, err := client.CoreV1().ConfigMaps("test-ns").Get(ctx, "egress-uma-config", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Failed to fetch configmap: %v", err)
	}
	if updated.Data["tokens.json"] != `{"access_token":"new"}` {
		t.Fatalf("ConfigMap not updated after retry, got %q", updated.Data["tokens.json"])
	}
}
