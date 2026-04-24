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

func ValidServiceUri(uri string) (string, string, error) {
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

	// Find the Service Description
	var service *model.Service
	for svcQuery := range store.Match(nil, rdfgo.IRI.RDF.Type, model.Agg("Service"), nil) {
		if service != nil {
			return nil, errors.New("multiple agg:Service found; expected exactly one")
		}

		svc := svcQuery.GetSubject()

		// Get application
		var application *model.Application
		for appQuery := range store.Match(svc, model.Agg("applies"), nil, nil) {
			if application != nil {
				return nil, errors.New("multiple agg:applies found; expected exactly one")
			}

			app := appQuery.GetObject()

			// Get applied transformation
			var tf *model.Transformation
			var err error
			for tfQuery := range store.Match(app, model.FnOC("applies"), nil, nil) {
				tfUri := strings.Trim(tfQuery.GetObject().ToString(), "<>")
				// Load and parse transformation
				tf, err = LoadTransformationCR(tfUri)
				if err != nil {
					return nil, err
				}
			}

			// Get application parameters
			params := make(map[string]rdfgo.ITerm)
			for bindingQuery := range store.Match(app, model.FnOC("parameterBinding"), nil, nil) {
				binding := bindingQuery.GetObject()
				for paramQuery := range store.Match(binding, model.FnOC("boundParameter"), nil, nil) {
					paramUri := strings.Trim(paramQuery.GetObject().ToString(), "<>")
					for valueQuery := range store.Match(binding, model.FnOC("boundToTerm"), nil, nil) {
						value := valueQuery.GetObject()
						params[paramUri] = value
					}
				}
			}

			// Check if all parameters have an input
			// TODO: check if all required parameters have an input
			if len(params) != len(tf.Params) {
				return nil, fmt.Errorf("Not enough inputs provided: %d (expected: %d)", len(params), len(tf.Params))
			}

			application = &model.Application{
				Transformation: tf,
				Params:         params,
			}
		}

		service = &model.Service{
			URI:         strings.Trim(svc.ToString(), "<>"),
			Application: *application,
		}
	}

	// Enforce exactly one service description
	// TODO: allow multiple
	if service == nil {
		return nil, errors.New("no agg:Service found in FnO description")
	}

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
		predUri, exists := application.Transformation.Predicates[paramKey]
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
