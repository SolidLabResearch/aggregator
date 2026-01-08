package registration

import (
	"aggregator/model"
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func authToken(t *testing.T, webID string) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"webid": webID,
	})
	tokenString, err := token.SignedString([]byte("test-secret"))
	if err != nil {
		t.Fatalf("Failed to sign test token: %v", err)
	}
	return tokenString
}

func setDisableAuth(t *testing.T, value bool) {
	t.Helper()

	original := model.DisableAuth
	model.DisableAuth = value
	t.Cleanup(func() { model.DisableAuth = original })
}

func setAllowedRegistrationTypes(t *testing.T, types ...string) {
	t.Helper()

	original := model.AllowedRegistrationTypes
	model.AllowedRegistrationTypes = append([]string(nil), types...)
	t.Cleanup(func() { model.AllowedRegistrationTypes = original })
}

func TestRegistrationHandler_MethodNotAllowed(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/registration", nil)

	RegistrationHandler(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("Expected 405 Method Not Allowed, got %d", rec.Code)
	}
}

func TestRegistrationHandler_Post_MissingAuth(t *testing.T) {
	setDisableAuth(t, true)
	setAllowedRegistrationTypes(t, "provision", "authorization_code", "client_credentials", "device_code")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/registration", bytes.NewBufferString(`{"registration_type":"provision"}`))
	req.Header.Set("Content-Type", "application/json")

	RegistrationHandler(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 Unauthorized, got %d", rec.Code)
	}
}

func TestRegistrationHandler_Post_InvalidJSON(t *testing.T) {
	setDisableAuth(t, true)
	setAllowedRegistrationTypes(t, "provision", "authorization_code", "client_credentials", "device_code")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/registration", bytes.NewBufferString(`{invalid`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken(t, "https://alice.example/webid#me"))

	RegistrationHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 Bad Request, got %d", rec.Code)
	}
}

func TestRegistrationHandler_Post_MissingRegistrationType(t *testing.T) {
	setDisableAuth(t, true)
	setAllowedRegistrationTypes(t, "provision", "authorization_code", "client_credentials", "device_code")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/registration", bytes.NewBufferString(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken(t, "https://alice.example/webid#me"))

	RegistrationHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 Bad Request, got %d", rec.Code)
	}
}

func TestRegistrationHandler_Post_UnsupportedRegistrationType(t *testing.T) {
	setDisableAuth(t, true)
	setAllowedRegistrationTypes(t, "provision", "authorization_code", "client_credentials", "device_code")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/registration", bytes.NewBufferString(`{"registration_type":"unknown"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken(t, "https://alice.example/webid#me"))

	RegistrationHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 Bad Request, got %d", rec.Code)
	}
}

func TestRegistrationHandler_Post_ProvisionUpdateNotSupported(t *testing.T) {
	setDisableAuth(t, true)
	setAllowedRegistrationTypes(t, "provision", "authorization_code", "client_credentials", "device_code")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/registration", bytes.NewBufferString(`{"registration_type":"provision","aggregator_id":"agg-1"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken(t, "https://alice.example/webid#me"))

	RegistrationHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 Bad Request, got %d", rec.Code)
	}
}

func TestRegistrationHandler_Post_NoneUpdateNotSupported(t *testing.T) {
	setDisableAuth(t, true)
	setAllowedRegistrationTypes(t, "none")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/registration", bytes.NewBufferString(`{"registration_type":"none","aggregator_id":"agg-1"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken(t, "https://alice.example/webid#me"))

	RegistrationHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 Bad Request, got %d", rec.Code)
	}
}

func TestRegistrationHandler_Post_DeviceCode_NotImplemented(t *testing.T) {
	setDisableAuth(t, true)
	setAllowedRegistrationTypes(t, "provision", "authorization_code", "client_credentials", "device_code")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/registration", bytes.NewBufferString(`{"registration_type":"device_code"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken(t, "https://alice.example/webid#me"))

	RegistrationHandler(rec, req)

	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("Expected 501 Not Implemented, got %d", rec.Code)
	}
}

func TestRegistrationHandler_Post_AuthorizationCode_MissingAuthorizationServer(t *testing.T) {
	setDisableAuth(t, true)
	setAllowedRegistrationTypes(t, "provision", "authorization_code", "client_credentials", "device_code")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/registration", bytes.NewBufferString(`{"registration_type":"authorization_code","client_id":"https://app.example/client.json"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken(t, "https://alice.example/webid#me"))

	RegistrationHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 Bad Request, got %d", rec.Code)
	}
}

func TestRegistrationHandler_Post_AuthorizationCode_MissingClientID(t *testing.T) {
	setDisableAuth(t, true)
	setAllowedRegistrationTypes(t, "provision", "authorization_code", "client_credentials", "device_code")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/registration", bytes.NewBufferString(`{"registration_type":"authorization_code","authorization_server":"https://as.example"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken(t, "https://alice.example/webid#me"))

	RegistrationHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 Bad Request, got %d", rec.Code)
	}
}

func TestRegistrationHandler_Post_ClientCredentials_MissingFields(t *testing.T) {
	setDisableAuth(t, true)
	setAllowedRegistrationTypes(t, "provision", "authorization_code", "client_credentials", "device_code")

	testCases := []string{
		`{"registration_type":"client_credentials","authorization_server":"https://as.example"}`,
		`{"registration_type":"client_credentials","authorization_server":"https://as.example","webid":"https://alice.example/webid#me"}`,
		`{"registration_type":"client_credentials","authorization_server":"https://as.example","webid":"https://alice.example/webid#me","client_id":"client"}`,
	}

	for _, body := range testCases {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/registration", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+authToken(t, "https://alice.example/webid#me"))

		RegistrationHandler(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("Expected 400 Bad Request, got %d for body: %s", rec.Code, body)
		}
	}
}

func TestRegistrationHandler_Delete_InvalidJSON(t *testing.T) {
	setDisableAuth(t, true)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/registration", bytes.NewBufferString(`{invalid`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken(t, "https://alice.example/webid#me"))

	RegistrationHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 Bad Request, got %d", rec.Code)
	}
}

func TestRegistrationHandler_Delete_MissingAggregatorID(t *testing.T) {
	setDisableAuth(t, true)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/registration", bytes.NewBufferString(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+authToken(t, "https://alice.example/webid#me"))

	RegistrationHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 Bad Request, got %d", rec.Code)
	}
}

func TestRegistrationHandler_Delete_Unauthenticated(t *testing.T) {
	setDisableAuth(t, true)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/registration", bytes.NewBufferString(`{"aggregator_id":"agg-1"}`))
	req.Header.Set("Content-Type", "application/json")

	RegistrationHandler(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 Unauthorized, got %d", rec.Code)
	}
}
