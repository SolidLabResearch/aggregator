package instance

import (
	"aggregator/model"
	"errors"
	"fmt"
	"sync"
	"time"
)

// AggregatorInstance represents a deployed aggregator for a user
type AggregatorInstance struct {
	AggregatorID        string
	OwnerID             string
	RegistrationType    string
	AuthorizationServer string
	BaseURL             string
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

var (
	// In-memory storage for aggregator instances
	aggregatorInstances   = make(map[string]*AggregatorInstance)
	aggregatorInstancesMu sync.RWMutex

	// Index by owner ID for ownership checks
	ownerIndex   = make(map[string][]string) // OwnerID -> []AggregatorID
	ownerIndexMu sync.RWMutex
)

// storeAggregatorInstance stores or updates an aggregator instance
func storeAggregatorInstance(instance *AggregatorInstance) {
	aggregatorInstancesMu.Lock()
	defer aggregatorInstancesMu.Unlock()

	aggregatorInstances[instance.AggregatorID] = instance

	// Update owner index
	ownerIndexMu.Lock()
	defer ownerIndexMu.Unlock()

	// Check if already in index
	aggregatorIDs := ownerIndex[instance.OwnerID]
	found := false
	for _, id := range aggregatorIDs {
		if id == instance.AggregatorID {
			found = true
			break
		}
	}
	if !found {
		ownerIndex[instance.OwnerID] = append(aggregatorIDs, instance.AggregatorID)
	}
}

// ListPublicAggregators lists all public aggregator instances (for 'none' registration type)
func ListPublicAggregators() ([]*AggregatorInstance, error) {
	return ListAggregatorsByOwner("")
}

// ListAggregatorssByOwner lists all aggregator instances owned by a user
func ListAggregatorsByOwner(ownerID string) ([]*AggregatorInstance, error) {
	ownerIndexMu.RLock()
	aggregatorIDs, exists := ownerIndex[ownerID]
	ownerIndexMu.RUnlock()

	if !exists {
		return nil, nil
	}

	instances := make([]*AggregatorInstance, len(aggregatorIDs))
	for i, id := range aggregatorIDs {
		instance, err := GetAggregatorInstance(id)
		if err != nil {
			return nil, err
		}
		instances[i] = instance
	}

	return instances, nil
}

// getAggregatorInstance retrieves an aggregator instance by ID
func GetAggregatorInstance(aggregatorID string) (*AggregatorInstance, error) {
	aggregatorInstancesMu.RLock()
	defer aggregatorInstancesMu.RUnlock()

	instance, exists := aggregatorInstances[aggregatorID]
	if !exists {
		return nil, errors.New("aggregator not found")
	}

	return instance, nil
}

// deleteAggregatorInstance removes an aggregator instance
func DeleteAggregatorInstance(aggregatorID string) error {
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

	aggregatorIDs := ownerIndex[instance.OwnerID]
	for i, id := range aggregatorIDs {
		if id == aggregatorID {
			ownerIndex[instance.OwnerID] = append(aggregatorIDs[:i], aggregatorIDs[i+1:]...)
			break
		}
	}

	return nil
}

// checkOwnership verifies that the user ID owns the aggregator
func (instance *AggregatorInstance) HasOwnership(id string) bool {
	return instance.OwnerID == id
}

// createAggregatorInstanceRecord creates a new aggregator instance record
func CreateAggregatorInstanceRecord(
	ownerID string,
	registrationType string,
	authorizationServer string,
	aggregatorID string,
) *AggregatorInstance {
	now := time.Now()

	instance := &AggregatorInstance{
		AggregatorID:        aggregatorID,
		OwnerID:             ownerID,
		RegistrationType:    registrationType,
		AuthorizationServer: authorizationServer,
		BaseURL:             fmt.Sprintf("%s/%s", model.ExternalURL(), aggregatorID),
		CreatedAt:           now,
		UpdatedAt:           now,
	}

	storeAggregatorInstance(instance)
	return instance
}
