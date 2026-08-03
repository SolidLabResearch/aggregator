package model

import (
	"aggregator/util"
	"context"
	"fmt"
	"strings"

	"github.com/maartyman/rdfgo"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var FnoDescriptionGVR = schema.GroupVersionResource{
	Group:    "aggregator.example.org",
	Version:  "v1alpha1",
	Resource: "fnodescriptions",
}

type FnoDescription struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec FnoDescriptionSpec `json:"spec"`
}

type FnoDescriptionSpec struct {
	Type        string `json:"type"`        // deployment-function | implementation
	Description string `json:"description"` // Turtle RDF

	ServiceConfigurationRef Reference `json:"serviceConfigurationRef,omitempty"`
}

type Reference struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

type FnoDescriptionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FnoDescription `json:"items"`
}

func LoadFnoDescription(
	ctx context.Context,
	name, namespace string,
) (*FnoDescription, error) {

	obj, err := DynamicClient.
		Resource(FnoDescriptionGVR).
		Namespace(namespace).
		Get(ctx, strings.ToLower(name), metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	var fno FnoDescription

	err = runtime.DefaultUnstructuredConverter.
		FromUnstructured(obj.Object, &fno)
	if err != nil {
		return nil, err
	}

	return &fno, nil
}

type DeploymentFunction struct {
	Base       string            `json:"base,omitempty"`
	URI        string            `json:"uri"`
	FnO        string            `json:"-"`
	Params     map[string]string `json:"params,omitempty"`
	Outputs    map[string]string `json:"outputs,omitempty"`
	Predicates map[string]string `json:"predicates,omitempty"`
}

func LoadDeploymentFunction(uri string) (*DeploymentFunction, *ServiceConfiguration, error) {
	id, err := util.StripPrefix(uri, ExternalServerURL()+DeploymentCatalog+"#")
	if err != nil {
		return nil, nil, fmt.Errorf("invalid deployment function URI %q: %w", uri, err)
	}

	// Load function description
	ctx := context.Background()
	fno, err := LoadFnoDescription(ctx, id, Namespace)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load Fno Description: %w", err)
	}

	if fno.Spec.ServiceConfigurationRef.Name == "" {
		return nil, nil, fmt.Errorf(
			"FnoDescription %q has no serviceConfigurationRef",
			id,
		)
	}

	// Load service configuration
	svcConfig, err := LoadServiceConfiguration(ctx, fno.Spec.ServiceConfigurationRef.Name, Namespace)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load Service Configuration: %w", err)
	}

	t := &DeploymentFunction{
		Base: ExternalServerURL() + DeploymentCatalog + "#",
		URI:  uri,
		FnO:  fno.Spec.Description,
	}

	// Parse FnO
	t.ParseDeploymentFunction()

	return t, svcConfig, nil
}

func (tf *DeploymentFunction) ParseDeploymentFunction() {
	tf.Params = map[string]string{}
	tf.Outputs = map[string]string{}
	tf.Predicates = map[string]string{}

	quadStream, errChan := rdfgo.Parse(
		strings.NewReader(tf.FnO),
		rdfgo.ParserOptions{
			Format:  "text/turtle",
			BaseIRI: ExternalServerURL() + DeploymentCatalog + "#",
		},
	)

	go func() {
		for parseErr := range errChan {
			if parseErr != nil {
				logrus.WithError(parseErr).Warnf("Error parsing deployment function description for <%s>", tf.URI)
			}
		}
	}()

	store := rdfgo.NewStore()
	store.Import(quadStream)

	// Get parameters
	for listQuad := range store.Match(rdfgo.NewNamedNode(tf.URI), FnO("expects"), nil, nil) {
		for _, param := range util.RDFListToSlice(store, listQuad.GetObject()) {
			for predQuad := range store.Match(param, FnO("predicate"), nil, nil) {
				predUri := strings.Trim(predQuad.GetObject().ToString(), "<>")
				paramUri := strings.Trim(param.ToString(), "<>")
				tf.Predicates[predUri] = paramUri
				tf.Params[paramUri] = predUri
			}
		}
	}

	// Get outputs
	for listQuad := range store.Match(rdfgo.NewNamedNode(tf.URI), FnO("returns"), nil, nil) {
		for _, output := range util.RDFListToSlice(store, listQuad.GetObject()) {
			for predQuad := range store.Match(output, FnO("predicate"), nil, nil) {
				predUri := strings.Trim(predQuad.GetObject().ToString(), "<>")
				outputUri := strings.Trim(output.ToString(), "<>")
				tf.Predicates[predUri] = outputUri
				tf.Outputs[outputUri] = predUri
			}
		}
	}
}

type DeploymentRequest struct {
	Function *DeploymentFunction
	Bindings map[string]rdfgo.ITerm
}
