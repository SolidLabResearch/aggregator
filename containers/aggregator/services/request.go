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
	model.TransformationCatalog: {},
	model.ServiceCollection:     {},
	"aggregator":                {},
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

		// Find the transformation via aggr:performs
		var tf *model.Transformation
		var svcConfig *model.ServiceConfiguration
		for tfQuery := range store.Match(nil, model.Agg("performs"), nil, nil) {
			if tf != nil {
				log.Error("Multiple aggr:performs triples found; expected exactly one")
				return nil, errors.New("multiple aggr:performs triples found; expected exactly one")
			}
			tfUri := strings.Trim(tfQuery.GetObject().ToString(), "<>")
			log.WithField("transformation_uri", tfUri).Debug("Found aggr:performs triple, loading transformation")

			// Load transformation configuration
			var err error
			tf, svcConfig, err = model.LoadTransformation(tfUri)
			if err != nil {
				log.WithError(err).WithField("transformation_uri", tfUri).Error("Failed to load transformation")
				return nil, err
			}
			log.WithField("transformation_uri", tfUri).Debug("Successfully loaded transformation")
		}

		if tf == nil {
			log.Error("No aggr:performs triple found")
			return nil, errors.New("no valid transformation was requested using aggr:performs")
		}

		// Bind inputs using predicates
		bindings := make(map[string]rdfgo.ITerm)
		for _, pred := range tf.Params {
			for predQuery := range store.Match(reqQuery.GetSubject(), rdfgo.NewNamedNode(pred), nil, nil) {
				bindings[pred] = predQuery.GetObject()
			}
		}

		if len(bindings) != len(tf.Params) {
			log.WithFields(logrus.Fields{
				"inputs_provided": len(bindings),
				"inputs_expected": len(tf.Params),
			}).Error("Parameter count mismatch")
			return nil, fmt.Errorf("not enough inputs provided: %d (expected: %d)", len(bindings), len(tf.Params))
		}

		service = &model.Service{
			FullPath: requestedPath,
			Application: &model.Application{
				Transformation: tf,
				Bindings:       bindings,
			},
			Configuration: svcConfig,
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
