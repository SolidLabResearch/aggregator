package auth

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestDeleteResourcesDoesNotDeadlockAboveConcurrencyLimit(t *testing.T) {
	resourceIndexMu.Lock()
	originalIndex := resourceIndex
	resourceIndex = make(map[string]ResourceData)
	for _, id := range []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"} {
		resourceIndex[id] = ResourceData{}
	}
	resourceIndexMu.Unlock()

	originalDelete := deleteResourceForShutdown
	var calls atomic.Int32
	deleteResourceForShutdown = func(string) error {
		calls.Add(1)
		return nil
	}
	t.Cleanup(func() {
		resourceIndexMu.Lock()
		resourceIndex = originalIndex
		resourceIndexMu.Unlock()
		deleteResourceForShutdown = originalDelete
	})

	done := make(chan error, 1)
	go func() { done <- DeleteResources() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("DeleteResources returned an error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("DeleteResources deadlocked")
	}
	if calls.Load() != 11 {
		t.Fatalf("expected 11 deletions, got %d", calls.Load())
	}
}
