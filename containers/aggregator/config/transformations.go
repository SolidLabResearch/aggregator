package config

import (
	"aggregator/auth"
	"aggregator/model"
	"fmt"
	"net/http"
	"strconv"

	"github.com/sirupsen/logrus"
)

type DeploymentCatalog struct {
	etag        int
	description string
}

func InitDeploymentCatalog(mux *http.ServeMux) error {
	logrus.Debugf("Initializing deployment catalog at %s", model.DeploymentCatalog)

	catalog := DeploymentCatalog{
		etag:        0,
		description: hardcodedInstanceDeployments,
	}

	// Register HTTP handler
	mux.HandleFunc(model.DeploymentCatalog, catalog.HandleDeploymentsEndpoint)
	logrus.Infof("Handler registered at %s", model.DeploymentCatalog)

	// Register catalog resource and policy
	fullURL := model.ExternalBaseURL() + model.DeploymentCatalog
	if err := auth.RegisterResource(fullURL, []model.Scope{model.Read}); err != nil {
		return fmt.Errorf("failed to register resource %s: %w", fullURL, err)
	}
	if err := auth.DefinePolicy(fullURL, []model.Scope{model.Read}); err != nil {
		return fmt.Errorf("failed to define policy for resource %s: %w", fullURL, err)
	}

	logrus.Infof("Initialized deployment catalog at %s", model.DeploymentCatalog)
	return nil
}

func (catalog DeploymentCatalog) HandleDeploymentsEndpoint(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "HEAD":
		catalog.head(w, r)
	case "GET":
		catalog.get(w, r)
	default:
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

func (catalog *DeploymentCatalog) head(w http.ResponseWriter, _ *http.Request) {
	header := w.Header()
	header.Set("ETag", strconv.Itoa(catalog.etag))
	header.Set("Content-Type", "text/turtle")
}

func (catalog *DeploymentCatalog) get(w http.ResponseWriter, _ *http.Request) {
	header := w.Header()
	header.Set("ETag", strconv.Itoa(catalog.etag))
	header.Set("Content-Type", "text/turtle")
	_, err := w.Write([]byte(catalog.description))
	if err != nil {
		http.Error(w, "error when writing body", http.StatusInternalServerError)
	}
}

const hardcodedInstanceDeployments = `
@prefix aggr: <https://w3id.org/aggregator#> .

<> a aggr:DeploymentCatalog .
`
