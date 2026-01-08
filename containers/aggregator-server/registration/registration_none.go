package registration

import (
	"aggregator/model"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

func handleNoneFlow(w http.ResponseWriter, req model.RegistrationRequest, ownerWebID string) {
	if req.AggregatorID != "" {
		http.Error(w, "none updates are not supported", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	namespace, err := createNamespaceForAggregator(ownerWebID, "", ctx)
	if err != nil {
		logrus.WithError(err).Error("Failed to create namespace")
		http.Error(w, "Failed to create namespace", http.StatusInternalServerError)
		return
	}

	if err := deployAggregatorResources(namespace, "", "", "", "", ownerWebID, "", ctx); err != nil {
		logrus.WithError(err).Error("Failed to deploy aggregator")
		http.Error(w, "Failed to deploy aggregator", http.StatusInternalServerError)
		return
	}

	instance := createAggregatorInstanceRecord(
		ownerWebID,
		"none",
		"",
		namespace,
		"",
		"",
	)

	response := model.RegistrationResponse{
		AggregatorID: instance.AggregatorID,
		Aggregator:   instance.BaseURL,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logrus.WithError(err).Error("Failed to write response")
	}
}
