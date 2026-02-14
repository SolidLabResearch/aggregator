package instance

import (
	"aggregator/model"
	"fmt"
	"strings"
	"testing"
)

func TestCreateAggregatorInstanceRecord_BaseURLUsesID(t *testing.T) {
	originalProtocol := model.Protocol
	originalHost := model.ExternalHost
	model.Protocol = "http"
	model.ExternalHost = "aggregator.local"
	t.Cleanup(func() {
		model.Protocol = originalProtocol
		model.ExternalHost = originalHost
	})

	id := "ns-test-123"
	instance := CreateAggregatorInstanceRecord(
		"https://owner.example/webid#me",
		"none",
		"",
		id,
	)
	t.Cleanup(func() {
		_ = DeleteAggregatorInstance(instance.AggregatorID)
	})

	expected := fmt.Sprintf("%s://%s/%s", model.Protocol, model.ExternalHost, id)
	actual := strings.TrimRight(instance.BaseURL, "/")
	if actual != expected {
		t.Fatalf("Expected BaseURL %q, got %q", expected, instance.BaseURL)
	}
}
