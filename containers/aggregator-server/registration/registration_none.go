package registration

import (
	"aggregator/instance"
	"aggregator/model"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

func handleNoneFlow(w http.ResponseWriter, req model.RegistrationRequest) {
	if req.AggregatorID != "" {
		http.Error(w, "none updates are not supported", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	aggregatorId, err := instance.DeployAggregator("", "", ctx)
	if err != nil {
		logrus.WithError(err).Error("Failed to deploy aggregator")
		http.Error(w, "Failed to deploy aggregator", http.StatusInternalServerError)
		return
	}

	inst := instance.CreateAggregatorInstanceRecord(
		"",
		"none",
		"",
		aggregatorId,
	)

	response := model.RegistrationResponse{
		AggregatorID: aggregatorId,
		Aggregator:   inst.BaseURL,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logrus.WithError(err).Error("Failed to write response")
	}
}
