package integration_test

import (
	"context"
	"os"
	"testing"
	"time"

	"aggregator-integration-test/utils"
)

var Env *utils.TestEnvironment

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	var err error
	Env, err = utils.SetupTestEnvironment(ctx)
	if err != nil {
		panic("Failed to setup test environment: " + err.Error())
	}

	code := m.Run()

	if err := Env.Cleanup(); err != nil {
		panic("Failed to cleanup test environment: " + err.Error())
	}

	os.Exit(code)
}
