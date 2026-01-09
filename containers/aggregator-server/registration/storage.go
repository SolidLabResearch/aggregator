package registration

import (
	"aggregator/model"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
)

// TODO: Replace with persistent storage in DB
var (
	// In-memory storage for aggregator instances
	aggregatorInstances   = make(map[string]*model.AggregatorInstance)
	aggregatorInstancesMu sync.RWMutex

	// Index by owner WebID for ownership checks
	ownerIndex   = make(map[string][]string) // WebID -> []AggregatorID
	ownerIndexMu sync.RWMutex
)

// generateAggregatorID generates a unique opaque identifier for an aggregator
func generateAggregatorID() string {
	return "agg-" + uuid.New().String()
}

// storeAggregatorInstance stores or updates an aggregator instance
func storeAggregatorInstance(instance *model.AggregatorInstance) {
	aggregatorInstancesMu.Lock()
	defer aggregatorInstancesMu.Unlock()

	aggregatorInstances[instance.AggregatorID] = instance

	// Update owner index
	ownerIndexMu.Lock()
	defer ownerIndexMu.Unlock()

	// Check if already in index
	aggregatorIDs := ownerIndex[instance.OwnerWebID]
	found := false
	for _, id := range aggregatorIDs {
		if id == instance.AggregatorID {
			found = true
			break
		}
	}
	if !found {
		ownerIndex[instance.OwnerWebID] = append(aggregatorIDs, instance.AggregatorID)
	}
}

// getAggregatorInstance retrieves an aggregator instance by ID
func getAggregatorInstance(aggregatorID string) (*model.AggregatorInstance, error) {
	aggregatorInstancesMu.RLock()
	defer aggregatorInstancesMu.RUnlock()

	instance, exists := aggregatorInstances[aggregatorID]
	if !exists {
		return nil, errors.New("aggregator not found")
	}

	return instance, nil
}

// deleteAggregatorInstance removes an aggregator instance
func deleteAggregatorInstance(aggregatorID string) error {
	aggregatorInstancesMu.Lock()
	defer aggregatorInstancesMu.Unlock()

	instance, exists := aggregatorInstances[aggregatorID]
	if !exists {
		return errors.New("aggregator not found")
	}

	delete(aggregatorInstances, aggregatorID)

	// Update owner index
	ownerIndexMu.Lock()
	defer ownerIndexMu.Unlock()

	aggregatorIDs := ownerIndex[instance.OwnerWebID]
	for i, id := range aggregatorIDs {
		if id == aggregatorID {
			ownerIndex[instance.OwnerWebID] = append(aggregatorIDs[:i], aggregatorIDs[i+1:]...)
			break
		}
	}

	return nil
}

// checkOwnership verifies that the WebID owns the aggregator
func checkOwnership(aggregatorID string, webID string) error {
	instance, err := getAggregatorInstance(aggregatorID)
	if err != nil {
		return err
	}

	if instance.OwnerWebID != webID {
		return errors.New("not authorized")
	}

	return nil
}

// createAggregatorInstanceRecord creates a new aggregator instance record
func createAggregatorInstanceRecord(
	ownerWebID string,
	registrationType string,
	authorizationServer string,
	namespace string,
	accessToken string,
	refreshToken string,
) *model.AggregatorInstance {
	aggregatorID := generateAggregatorID()
	now := time.Now()

	instance := &model.AggregatorInstance{
		AggregatorID:        aggregatorID,
		OwnerWebID:          ownerWebID,
		RegistrationType:    registrationType,
		AuthorizationServer: authorizationServer,
		Namespace:           namespace,
		BaseURL:             model.GetAggregatorURL(namespace),
		AccessToken:         accessToken,
		RefreshToken:        refreshToken,
		CreatedAt:           now,
		UpdatedAt:           now,
	}

	storeAggregatorInstance(instance)
	return instance
}

// updateAggregatorInstanceTokens updates the tokens for an existing aggregator
func updateAggregatorInstanceTokens(aggregatorID string, accessToken string, refreshToken string) error {
	instance, err := getAggregatorInstance(aggregatorID)
	if err != nil {
		return err
	}

	instance.AccessToken = accessToken
	instance.RefreshToken = refreshToken
	instance.UpdatedAt = time.Now()

	storeAggregatorInstance(instance)
	return nil
}
