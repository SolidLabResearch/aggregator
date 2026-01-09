package integration_test

import (
	"context"
	"os"
	"testing"
	"time"

	"aggregator-integration-test/utils"
)

const (
	testAggregatorClientIDURL  = "http://aggregator.local/client.json"
	testAggregatorClientSecret = "AtctW4sdbmjcfF9gQJIf5RoK6T6wetwG"
	testProvisionClientID      = "provision-client-id"
	testProvisionClientSecret  = "provision-client-secret"
)

var testEnv *utils.TestEnvironment

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	var err error
	testEnv, err = utils.SetupTestEnvironment(ctx)
	if err != nil {
		panic("Failed to setup test environment: " + err.Error())
	}

	code := m.Run()

	if err := testEnv.Cleanup(); err != nil {
		panic("Failed to cleanup test environment: " + err.Error())
	}

	os.Exit(code)
}
