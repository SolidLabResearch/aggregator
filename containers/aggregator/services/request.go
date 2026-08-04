package services

import (
	"aggregator/model"
	"aggregator/util"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/maartyman/rdfgo"
	"github.com/sirupsen/logrus"
)

var idPattern = `^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
var idValidator = regexp.MustCompile(idPattern)

var forbidden = map[string]struct{}{
	model.DeploymentCatalog: {},
	model.ServiceCollection: {},
	"aggregator":            {},
}

func ValidServicePath(uri string) (string, string, error) {
	// Validate service path
	servicePath, err := util.StripPrefix(uri, model.ExternalBaseURL())
	if err != nil {
		return "", "", fmt.Errorf("Invalid execution URI: %w", err)
	}
	if _, exists := forbidden[servicePath]; exists {
		return "", "", errors.New("Invalid execution URI: path reserved for spec endpoints")
	}
	serviceId := strings.ReplaceAll(strings.Trim(servicePath, "/"), "/", "-")

	// Validate service ID
	if !idValidator.MatchString(serviceId) {
		return "", "", fmt.Errorf("Service ID must match %s", idPattern)
	}

	return servicePath, serviceId, nil
}

func ParseRequestBody(fno string, format string) (*model.Service, error) {
	log := logrus.WithField("func", "ParseRequestBody")
	log.WithField("body_length", len(fno)).Debug("Starting to parse FnO description")

	quadStream, errChan := rdfgo.Parse(
		strings.NewReader(fno),
		rdfgo.ParserOptions{Format: format},
	)

	go func() {
		for parseErr := range errChan {
			if parseErr != nil {
				logrus.WithError(parseErr).Warn("Error parsing FnO description")
			}
		}
	}()

	store := rdfgo.NewStore()
	store.Import(quadStream)
	log.Debug("Imported quads into store")

	// Find and parse the Service Request
	var service *model.Service
	for reqQuery := range store.Match(nil, rdfgo.IRI.RDF.Type, model.Agg("ServiceRequest"), nil) {
		// TODO blank node service request
		// Validate requested URI
		requestedPath := strings.Trim(reqQuery.GetSubject().ToString(), "<>")
		log.WithField("requested uri", requestedPath).Debug("Found aggr:ServiceRequest")

		if service != nil {
			log.Error("Multiple aggr:ServiceRequest found; expected exactly one")
			return nil, errors.New("multiple aggr:ServiceRequest found; expected exactly one")
		}

		// Find the deployment function selected by this service request.
		var definition *model.ResolvedDeployment
		for functionQuery := range store.Match(reqQuery.GetSubject(), model.Agg("deploymentFunction"), nil, nil) {
			if definition != nil {
				log.Error("Multiple aggr:deploymentFunction triples found; expected exactly one")
				return nil, errors.New("multiple aggr:deploymentFunction triples found; expected exactly one")
			}
			functionURI := strings.Trim(functionQuery.GetObject().ToString(), "<>")
			log.WithField("deployment_function_uri", functionURI).Debug("Loading requested deployment function")

			// Load transformation configuration
			var err error
			definition, err = model.LoadDeploymentFunction(functionURI)
			if err != nil {
				log.WithError(err).WithField("deployment_function_uri", functionURI).Error("Failed to load deployment function")
				return nil, err
			}
		}

		if definition == nil {
			log.Error("No aggr:deploymentFunction triple found")
			return nil, errors.New("no valid deployment function was requested using aggr:deploymentFunction")
		}

		// Bind inputs using predicates
		bindings := make(map[string]rdfgo.ITerm)
		for _, parameter := range definition.Parameters {
			for predQuery := range store.Match(reqQuery.GetSubject(), rdfgo.NewNamedNode(parameter.Predicate), nil, nil) {
				if _, exists := bindings[parameter.Predicate]; exists {
					return nil, fmt.Errorf("multiple values provided for input %q", parameter.Name)
				}
				bindings[parameter.Predicate] = predQuery.GetObject()
			}
			if parameter.Required {
				if _, exists := bindings[parameter.Predicate]; !exists {
					return nil, fmt.Errorf("required input %q was not provided", parameter.Name)
				}
			}
		}

		service = &model.Service{
			FullPath: requestedPath,
			Deployment: &model.DeploymentRequest{
				Bindings:   bindings,
				Definition: definition,
			},
		}
		log.WithField("service_uri", service.FullPath).Debug("Successfully built Service")
	}

	if service == nil {
		log.Error("Unable to build aggr:Service from request")
		return nil, errors.New("Unable to build aggr:Service from request")
	}

	log.WithField("service_uri", service.FullPath).Info("Successfully parsed FnO description")
	return service, nil
}
