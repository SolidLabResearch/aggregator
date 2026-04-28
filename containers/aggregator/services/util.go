package services

import (
	"aggregator/model"
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/maartyman/rdfgo"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
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
	servicePath, err := StripPrefix(uri, model.ExternalBaseURL())
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
		for tfQuery := range store.Match(nil, model.FnOC("applies"), nil, nil) {
			if tf != nil {
				log.Error("Multiple fnoc:applies triples found; expected exactly one")
				return nil, errors.New("multiple fnoc:applies found; expected exactly one")
			}
			tfUri := strings.Trim(tfQuery.GetObject().ToString(), "<>")
			log.WithField("transformation_uri", tfUri).Debug("Found fnoc:applies triple, loading transformation")

			var err error
			tf, err = LoadTransformationCR(tfUri)
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
		params := make(map[string]rdfgo.ITerm)
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
				params[paramUri] = value
			}
		}

		log.WithFields(logrus.Fields{
			"params_provided": len(params),
			"params_expected": len(tf.Params),
		}).Debug("Finished collecting parameter bindings")

		if len(params) != len(tf.Params) {
			log.WithFields(logrus.Fields{
				"params_provided": len(params),
				"params_expected": len(tf.Params),
			}).Error("Parameter count mismatch")
			return nil, fmt.Errorf("not enough inputs provided: %d (expected: %d)", len(params), len(tf.Params))
		}

		service = &model.Service{
			FullPath: strings.Trim(svcQuery.GetSubject().ToString(), "<>"),
			Application: model.Application{
				Transformation: tf,
				Params:         params,
			},
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

func LoadTransformationCR(uri string) (*model.Transformation, error) {
	id, err := StripPrefix(uri, model.ExternalServerURL()+model.TransformationCatalog+"#")
	if err != nil {
		return nil, fmt.Errorf("invalid transformation URI %q: %w", uri, err)
	}

	// Define GVR
	gvr := schema.GroupVersionResource{
		Group:    "agg.idlab.ugent.be",
		Version:  "v1",
		Resource: "transformations",
	}

	// List CRs in the namespace
	crList, err := model.DynamicClient.
		Resource(gvr).
		Namespace(model.Namespace).
		List(context.TODO(), v1.ListOptions{})
	if err != nil {
		return nil, err
	}

	// Search for the transformation with matching id
	for _, item := range crList.Items {
		spec, ok := item.Object["spec"].(map[string]interface{})
		if !ok {
			continue
		}

		if getString(spec, "id") != id {
			continue
		}

		t := &model.Transformation{
			Base:          model.ExternalServerURL() + model.TransformationCatalog + "#",
			URI:           uri,
			Image:         getString(spec, "image"),
			FnO:           getString(spec, "fno"),
			InputMapping:  make(map[string]string),
			OutputMapping: make(map[string]model.OutputMapping),
		}

		// Parse FnO
		t.ParseTransformation()

		// Populate inputMapping
		if env, ok := spec["inputMapping"].(map[string]interface{}); ok {
			for k, v := range env {
				t.InputMapping[k] = fmt.Sprint(v)
			}
		}
		if len(t.Params) != len(t.InputMapping) {
			logrus.WithFields(logrus.Fields{
				"params":   t.Params,
				"mappings": t.InputMapping,
			}).Debugf("Parsed parameters and mappings")
			return nil, fmt.Errorf("transformation CR %s has an incorrect amount of input mappings", id)
		}

		// Populate outputMapping
		if out, ok := spec["outputMapping"].(map[string]interface{}); ok {
			for k, v := range out {
				if mapping, ok := v.(map[string]interface{}); ok {

					var port int32

					switch p := mapping["port"].(type) {
					case int32:
						port = p
					case int:
						port = int32(p)
					case int64:
						port = int32(p)
					case float64:
						port = int32(p)
					}

					path := fmt.Sprint(mapping["path"])

					t.OutputMapping[k] = model.OutputMapping{
						Port: port,
						Path: path,
					}
				}
			}
		}
		if len(t.Outputs) != len(t.OutputMapping) {
			logrus.WithFields(logrus.Fields{
				"outputs":  t.Params,
				"mappings": t.OutputMapping,
			}).Debug("Parsed outputs and mappings")
			return nil, fmt.Errorf("transformation CR %s has an incorrect amount of output mappings", id)
		}

		return t, nil // Found the transformation, return
	}

	return nil, fmt.Errorf("transformation with id %q not found", id)
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		return fmt.Sprint(v)
	}
	return ""
}

func ParametersToEnvVars(application *model.Application) ([]corev1.EnvVar, error) {
	var envVars = []corev1.EnvVar{
		{Name: "LOG_LEVEL", Value: model.LogLevel.String()},
	}

	for paramKey, paramValue := range application.Params {
		predUri, exists := application.Transformation.Params[paramKey]
		if !exists {
			return nil, fmt.Errorf("no predicate found for parameter %q", paramKey)
		}

		pred, err := StripPrefix(predUri, model.ExternalServerURL()+model.TransformationCatalog+"#")
		if err != nil {
			return nil, fmt.Errorf("failed to parse predicate %q: %w", predUri, err)
		}

		envKey, exists := application.Transformation.InputMapping[pred]
		if !exists {
			return nil, fmt.Errorf("no environment variable mapping found for parameter %q", paramKey)
		}

		envVars = append(envVars, corev1.EnvVar{
			Name:  envKey,
			Value: strings.Trim(paramValue.GetValue(), "<>"),
		})
	}
	return envVars, nil
}

func StripPrefix(uri string, prefix string) (string, error) {
	id, found := strings.CutPrefix(uri, prefix)
	if !found {
		return "", fmt.Errorf(
			"expected prefix %q",
			prefix,
		)
	}
	return id, nil
}
