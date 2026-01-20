package services

import (
	"aggregator/model"
	"context"
	"fmt"
	"strings"

	"github.com/maartyman/rdfgo"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var rdfType = rdfgo.NewNamedNode("http://www.w3.org/1999/02/22-rdf-syntax-ns#type")
var fnoExecution = rdfgo.NewNamedNode("https://w3id.org/function/ontology#Execution")
var fnoExecutes = rdfgo.NewNamedNode("https://w3id.org/function/ontology#executes")

func HandleServiceRequest(req model.ServiceRequest) (*model.Service, error) {
	// Parse the FnO description to extract executions
	exe, err := ParseRequestBody(req.Description)
	if err != nil {
		logrus.WithError(err).Error("Failed to parse FnO description")
		return nil, err
	}
	logrus.Infof("Processing execution: %s", exe.URI)

	// Load the corresponding transformation CR
	transformation, err := loadTransformationCR(exe.Transformation)
	if err != nil {
		logrus.WithError(err).Errorf("Failed to load transformation CR for %s", exe.Transformation)
		return nil, err
	}
	logrus.Infof("Loaded transformation: %+v", transformation)

	// Convert parameters to environment variables
	envVars, err := parametersToEnvVars(exe.Params, transformation.EnvMapping)
	if err != nil {
		logrus.WithError(err).Error("Failed to convert parameters to environment variables")
		return nil, err
	}
	logrus.Infof("Prepared env vars for execution %s: %+v", exe.URI, envVars)

	// Create service
	service, err := CreateAggregatorService(req, envVars, transformation.Image)
	if err != nil {
		logrus.WithError(err).Error("Failed to create service")
		return nil, err
	}
	logrus.Infof("Service created successfully: %+v", service)

	return service, nil
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
	executionsIter := store.Match(nil, rdfType, fnoExecution, nil)
	var executions []model.Execution
	for q := range executionsIter {
		exeUri := q.GetSubject().ToString()

		// Get transformation URI
		var transformationUri string
		for t := range store.Match(rdfgo.NewNamedNode(exeUri), fnoExecutes, nil, nil) {
			transformationUri = t.GetObject().ToString()
			break
		}

		// Get parameters
		params := make(map[string]string)
		for p := range store.Match(rdfgo.NewNamedNode(exeUri), nil, nil, nil) {
			if p.GetPredicate().Equals(rdfType) || p.GetPredicate().Equals(fnoExecutes) {
				continue
			}
			params[p.GetPredicate().ToString()] = p.GetObject().ToString()
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

func loadTransformationCR(uri string) (*model.Transformation, error) {
	id, err := UriToID(uri)
	if err != nil {
		return nil, fmt.Errorf("invalid transformation URI %q: %w", uri, err)
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
			ID:         getString(spec, "id"),
			Image:      getString(spec, "image"),
			EnvMapping: make(map[string]string),
		}

		// Populate EnvMapping
		if env, ok := spec["envMapping"].(map[string]interface{}); ok {
			for k, v := range env {
				t.EnvMapping[k] = fmt.Sprint(v)
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

func parametersToEnvVars(params map[string]string, envMapping map[string]string) ([]corev1.EnvVar, error) {
	var envVars = []corev1.EnvVar{
		{Name: "LOG_LEVEL", Value: model.LogLevel.String()},
	}
	for paramKey, paramValue := range params {
		pred, err := UriToID(paramKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse parameter key %q: %w", paramKey, err)
		}
		envKey, exists := envMapping[pred]
		if !exists {
			return nil, fmt.Errorf("no environment variable mapping found for parameter %q", paramKey)
		}
		envVars = append(envVars, corev1.EnvVar{
			Name:  envKey,
			Value: paramValue,
		})
	}
	return envVars, nil
}

func UriToID(uri string) (string, error) {
	id, found := strings.CutPrefix(uri, model.ExternalHost+"/config/transformations#")
	if !found {
		return "", fmt.Errorf("invalid URI base")
	}
	return id, nil
}
