package registration

import (
	"aggregator/model"
	"fmt"
	"strings"
	"testing"
)

func TestCreateAggregatorInstanceRecord_BaseURLUsesNamespace(t *testing.T) {
	originalProtocol := model.Protocol
	originalHost := model.ExternalHost
	model.Protocol = "http"
	model.ExternalHost = "aggregator.local"
	t.Cleanup(func() {
		model.Protocol = originalProtocol
		model.ExternalHost = originalHost
	})

	namespace := "ns-test-123"
	instance := createAggregatorInstanceRecord(
		"https://owner.example/webid#me",
		"none",
		"",
		namespace,
		"",
		"",
	)
	t.Cleanup(func() {
		_ = deleteAggregatorInstance(instance.AggregatorID)
	})

	expected := fmt.Sprintf("%s://%s/config/%s", model.Protocol, model.ExternalHost, namespace)
	actual := strings.TrimRight(instance.BaseURL, "/")
	if actual != expected {
		t.Fatalf("Expected BaseURL %q, got %q", expected, instance.BaseURL)
	}
}
