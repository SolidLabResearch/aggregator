package registration

import (
	"aggregator/model"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleProvisionFlow_MissingConfig(t *testing.T) {
	originalClientID := model.ProvisionClientID
	originalClientSecret := model.ProvisionClientSecret
	originalWebID := model.ProvisionWebID
	originalAuthServer := model.ProvisionAuthorizationServer
	t.Cleanup(func() {
		model.ProvisionClientID = originalClientID
		model.ProvisionClientSecret = originalClientSecret
		model.ProvisionWebID = originalWebID
		model.ProvisionAuthorizationServer = originalAuthServer
	})

	model.ProvisionClientID = ""
	model.ProvisionClientSecret = ""
	model.ProvisionWebID = ""
	model.ProvisionAuthorizationServer = ""

	recorder := httptest.NewRecorder()
	handleProvisionFlow(recorder, model.RegistrationRequest{RegistrationType: "provision"}, "https://owner.example/webid#me")

	resp := recorder.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected 500, got %d: %s", resp.StatusCode, string(bodyBytes))
	}

	bodyBytes, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(bodyBytes), "Provisioning configuration is not set") {
		t.Fatalf("Expected missing config error, got: %s", string(bodyBytes))
	}
}
