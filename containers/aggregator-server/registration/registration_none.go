package registration

import (
	"aggregator/instance"
	"aggregator/model"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

func handleNoneFlow(w http.ResponseWriter, req model.RegistrationRequest) {
	if req.AggregatorID != "" {
		http.Error(w, "none updates are not supported", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	aggregatorID := uuid.New().String()
	err := instance.DeployAggregator("", aggregatorID, "", ctx)
	if err != nil {
		logrus.WithError(err).Error("Failed to deploy aggregator")
		http.Error(w, "Failed to deploy aggregator", http.StatusInternalServerError)
		return
	}

	inst := instance.CreateAggregatorInstanceRecord(
		"",
		"none",
		"",
		aggregatorID,
	)

	response := model.RegistrationResponse{
		AggregatorID: aggregatorID,
		Aggregator:   inst.BaseURL,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logrus.WithError(err).Error("Failed to write response")
	}
}
