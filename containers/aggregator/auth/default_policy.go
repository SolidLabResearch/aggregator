package auth

import (
	"aggregator/model"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

type DefaultPolicy struct {
	ID       string          `json:"id"`
	Document json.RawMessage `json:"policy"`
}

type defaultPolicyRequest struct {
	AggregatorID     string          `json:"aggregator_id"`
	UserID           string          `json:"user_id"`
	ASURL            string          `json:"as_url"`
	Assigner         string          `json:"assigner"`
	PolicyManagement bool            `json:"policy_management,omitempty"`
	Document         json.RawMessage `json:"policy"`
}

var ErrDefaultPolicyNotFound = errors.New("default policy not found")

func CreateDefaultPolicy(document json.RawMessage) (DefaultPolicy, error) {
	return createDefaultPolicy(document, false)
}

func CreateOwnerDefaultPolicy(document json.RawMessage) (DefaultPolicy, error) {
	return createDefaultPolicy(document, true)
}

func createDefaultPolicy(document json.RawMessage, policyManagement bool) (DefaultPolicy, error) {
	assigner := model.ProvisionID
	if assigner == "" {
		assigner = model.Owner.UserId
	}
	body, err := json.Marshal(defaultPolicyRequest{
		AggregatorID:     model.ID,
		UserID:           model.Owner.UserId,
		ASURL:            model.Owner.AuthzServerURL,
		Assigner:         assigner,
		PolicyManagement: policyManagement,
		Document:         document,
	})
	if err != nil {
		return DefaultPolicy{}, err
	}
	response, err := model.HttpClient.Post(defaultPoliciesURL(), "application/json", bytes.NewReader(body))
	if err != nil {
		return DefaultPolicy{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		data, _ := io.ReadAll(response.Body)
		return DefaultPolicy{}, fmt.Errorf("default policy creation returned %d: %s", response.StatusCode, data)
	}
	var created DefaultPolicy
	if err := json.NewDecoder(response.Body).Decode(&created); err != nil {
		return DefaultPolicy{}, err
	}
	return created, nil
}

func ListDefaultPolicies() ([]DefaultPolicy, error) {
	request, err := http.NewRequest(http.MethodGet, defaultPoliciesURL()+"?aggregator_id="+url.QueryEscape(model.ID), nil)
	if err != nil {
		return nil, err
	}
	response, err := model.HttpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("default policy list returned %d", response.StatusCode)
	}
	var policies []DefaultPolicy
	if err := json.NewDecoder(response.Body).Decode(&policies); err != nil {
		return nil, err
	}
	return policies, nil
}

func DeleteDefaultPolicy(id string) error {
	endpoint := defaultPoliciesURL() + "?aggregator_id=" + url.QueryEscape(model.ID) + "&id=" + url.QueryEscape(id)
	request, err := http.NewRequest(http.MethodDelete, endpoint, nil)
	if err != nil {
		return err
	}
	response, err := model.HttpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return ErrDefaultPolicyNotFound
	}
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("default policy deletion returned %d", response.StatusCode)
	}
	return nil
}

func defaultPoliciesURL() string {
	return fmt.Sprintf("http://ingress-uma.%s.svc.cluster.local:8080/default-policies", model.Namespace)
}
