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

func ParseRequestBody(fno string) (*model.Service, error) {
	log := logrus.WithField("func", "ParseRequestBody")
	log.WithField("body_length", len(fno)).Debug("Starting to parse FnO description")

	quadStream, errChan := rdfgo.Parse(
		strings.NewReader(fno),
		rdfgo.ParserOptions{Format: "text/turtle"},
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

	// Find the Service
	var service *model.Service
	for svcQuery := range store.Match(nil, rdfgo.IRI.RDF.Type, model.Agg("Service"), nil) {
		svcSubject := svcQuery.GetSubject().ToString()
		log.WithField("service_uri", svcSubject).Debug("Found agg:Service triple")

		if service != nil {
			log.Error("Multiple agg:Service subjects found; expected exactly one")
			return nil, errors.New("multiple agg:Service found; expected exactly one")
		}

		// Verify exactly one agg:applies exists
		appCount := 0
		for range store.Match(nil, model.Agg("applies"), nil, nil) {
			appCount++
		}
		if appCount == 0 {
			log.Error("No agg:applies triple found")
			return nil, errors.New("no agg:applies found")
		}
		if appCount > 1 {
			log.Error("Multiple agg:applies triples found; expected exactly one")
			return nil, errors.New("multiple agg:applies found; expected exactly one")
		}

		// Find the transformation via fnoc:applies
		var tf *model.Transformation
		var svcConfig *model.ServiceConfiguration
		for tfQuery := range store.Match(nil, model.FnOC("applies"), nil, nil) {
			if tf != nil {
				log.Error("Multiple fnoc:applies triples found; expected exactly one")
				return nil, errors.New("multiple fnoc:applies found; expected exactly one")
			}
			tfUri := strings.Trim(tfQuery.GetObject().ToString(), "<>")
			log.WithField("transformation_uri", tfUri).Debug("Found fnoc:applies triple, loading transformation")

			var err error
			tf, svcConfig, err = model.LoadTransformation(tfUri)
			if err != nil {
				log.WithError(err).WithField("transformation_uri", tfUri).Error("Failed to load transformation")
				return nil, err
			}
			log.WithFields(logrus.Fields{
				"transformation_uri":    tfUri,
				"transformation_params": len(tf.Params),
			}).Debug("Successfully loaded transformation")
		}

		if tf == nil {
			log.Error("No fnoc:applies triple found")
			return nil, errors.New("no transformation applied")
		}

		// Collect parameter bindings — each binding node has exactly one boundParameter and one boundToTerm
		bindings := make(map[string]rdfgo.ITerm)
		for bindingQuery := range store.Match(nil, model.FnOC("parameterBinding"), nil, nil) {
			bindingNode := bindingQuery.GetObject()
			bindingLabel := bindingNode.ToString()
			log.WithField("binding_node", bindingLabel).Debug("Found fnoc:parameterBinding triple")

			// Get boundParameter for this binding node
			var paramUri string
			for paramQuery := range store.Match(bindingNode, model.FnOC("boundParameter"), nil, nil) {
				paramUri = strings.Trim(paramQuery.GetObject().ToString(), "<>")
				log.WithFields(logrus.Fields{
					"binding_node": bindingLabel,
					"param_uri":    paramUri,
				}).Debug("Found fnoc:boundParameter")
			}

			// Get boundToTerm for this binding node
			for valueQuery := range store.Match(bindingNode, model.FnOC("boundToTerm"), nil, nil) {
				value := valueQuery.GetObject()
				log.WithFields(logrus.Fields{
					"binding_node": bindingLabel,
					"param_uri":    paramUri,
					"value":        value.ToString(),
				}).Debug("Found fnoc:boundToTerm, binding parameter")

				// Get parameter predicate
				predUri, exists := tf.Params[paramUri]
				if !exists {
					log.WithFields(logrus.Fields{
						"binding_node": bindingLabel,
						"param_uri":    paramUri,
					}).Error("No predicate found for parameter")
					return nil, fmt.Errorf("no predicate found for parameter %q", paramUri)
				}
				bindings[predUri] = value
			}
		}

		if len(bindings) != len(tf.Params) {
			log.WithFields(logrus.Fields{
				"params_provided": len(bindings),
				"params_expected": len(tf.Params),
			}).Error("Parameter count mismatch")
			return nil, fmt.Errorf("not enough inputs provided: %d (expected: %d)", len(bindings), len(tf.Params))
		}

		service = &model.Service{
			FullPath: strings.Trim(svcQuery.GetSubject().ToString(), "<>"),
			Application: &model.Application{
				Transformation: tf,
				Bindings:       bindings,
			},
			Configuration: svcConfig,
		}
		log.WithField("service_uri", service.FullPath).Debug("Successfully built Service")
	}

	if service == nil {
		log.Error("No agg:Service triple found in FnO description")
		return nil, errors.New("no agg:Service found in FnO description")
	}

	log.WithField("service_uri", service.FullPath).Info("Successfully parsed FnO description")
	return service, nil
}
