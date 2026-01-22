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
}

func ValidServiceUri(uri string) (string, string, error) {
	// Validate service path
	servicePath, err := UriToID(uri, model.BaseUrl)
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

func ParseRequestBody(fno string) (model.Execution, error) {
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

	// Find all executions
	executionsIter := store.Match(nil, rdfgo.IRI.RDF.Type, model.FnO("Execution"), nil)
	var executions []model.Execution
	for q := range executionsIter {
		exeUri := q.GetSubject().ToString()
		exeUri = strings.Trim(exeUri, "<>")

		// Get transformation URI
		var transformationUri string
		for t := range store.Match(rdfgo.NewNamedNode(exeUri), model.FnO("executes"), nil, nil) {
			transformationUri = t.GetObject().ToString()
			transformationUri = strings.Trim(transformationUri, "<>")
			break
		}

		// Get parameters
		params := make(map[string]rdfgo.ITerm)
		for p := range store.Match(rdfgo.NewNamedNode(exeUri), nil, nil, nil) {
			if p.GetPredicate().Equals(rdfgo.IRI.RDF.Type) || p.GetPredicate().Equals(model.FnO("executes")) {
				continue
			}
			params[strings.Trim(p.GetPredicate().ToString(), "<>")] = p.GetObject()
		}

		executions = append(executions, model.Execution{
			URI:            exeUri,
			Transformation: transformationUri,
			Params:         params,
		})
	}

	// Enforce exactly one execution
	if len(executions) == 0 {
		return model.Execution{}, fmt.Errorf("no fno:Execution found in FnO description")
	}
	if len(executions) > 1 {
		return model.Execution{}, fmt.Errorf("multiple fno:Execution found; expected exactly one")
	}

	return executions[0], nil
}

func LoadTransformationCR(uri string) (*model.Transformation, error) {
	id, err := UriToID(uri, fmt.Sprintf("%s://%s/config/transformations#", model.Protocol, model.ExternalHost))
	if err != nil {
		return nil, fmt.Errorf("invalid transformation URI %q", uri)
	}

	// Define GVR
	gvr := schema.GroupVersionResource{
		Group:    "fno.knows.idlab.ugent.be",
		Version:  "v1",
		Resource: "transformations",
	}

	// List CRs in the namespace
	crList, err := model.DynamicClient.
		Resource(gvr).
		Namespace("aggregator-app").
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
			ID:            getString(spec, "id"),
			Image:         getString(spec, "image"),
			InputMapping:  make(map[string]string),
			OutputMapping: make(map[string]model.OutputMapping),
		}

		// Populate inputMapping
		if env, ok := spec["inputMapping"].(map[string]interface{}); ok {
			for k, v := range env {
				t.InputMapping[k] = fmt.Sprint(v)
			}
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

func ParametersToEnvVars(params map[string]rdfgo.ITerm, inputMapping map[string]string) ([]corev1.EnvVar, error) {
	var envVars = []corev1.EnvVar{
		{Name: "LOG_LEVEL", Value: model.LogLevel.String()},
	}
	for paramKey, paramValue := range params {
		pred, err := UriToID(paramKey, fmt.Sprintf("%s://%s/config/transformations#", model.Protocol, model.ExternalHost))
		if err != nil {
			return nil, fmt.Errorf("failed to parse parameter key %q: %w", paramKey, err)
		}
		envKey, exists := inputMapping[pred]
		if !exists {
			return nil, fmt.Errorf("no environment variable mapping found for parameter %q", paramKey)
		}
		envVars = append(envVars, corev1.EnvVar{
			Name:  envKey,
			Value: strings.Trim(paramValue.ToString(), "<>"),
		})
	}
	return envVars, nil
}

func parseOutputs(fno string, tfUri string) (string, error) {
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

	// Get all output predicates
	predicates := []string{}
	for output := range store.Match(rdfgo.NewNamedNode(tfUri), model.FnO("returns"), nil, nil) {
		for pred := range store.Match(output.GetObject(), model.FnO("predicate"), nil, nil) {
			predicates = append(predicates, strings.Trim(pred.GetObject().ToString(), "<>"))
		}
	}

	if len(predicates) == 0 {
		return "", errors.New("no outputs found")
	} else if len(predicates) > 1 {
		return "", errors.New("more than one output found")
	}

	return predicates[0], nil
}

func UriToID(uri string, prefix string) (string, error) {
	id, found := strings.CutPrefix(uri, prefix)
	if !found {
		return "", fmt.Errorf(
			"expected prefix %q",
			prefix,
		)
	}
	return id, nil
}
