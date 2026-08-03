package model

import (
	"aggregator/util"
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var ServiceConfigurationGVR = schema.GroupVersionResource{
	Group:    "aggregator.example.org",
	Version:  "v1alpha1",
	Resource: "serviceconfigurations",
}

type ServiceConfiguration struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ServiceConfigurationSpec `json:"spec"`
}

type ServiceConfigurationSpec struct {
	Prefixes map[string]string `json:"prefixes,omitempty"`

	InputMapping map[string]InputMapping `json:"inputMapping,omitempty"`
	Datasets     map[string]Dataset      `json:"datasets,omitempty"`

	ServiceMapping ServiceMapping `json:"serviceMapping"`
}

type InputMapping struct {
	ID string `json:"id"`
}

type Dataset struct {
	Title           string            `json:"title,omitempty"`
	Description     string            `json:"description,omitempty"`
	ExtraProperties map[string]string `json:"extraProperties,omitempty"`
	Distribution    *Distribution     `json:"distribution,omitempty"`
}

type Distribution struct {
	Title           string            `json:"title,omitempty"`
	Description     string            `json:"description,omitempty"`
	Access          *Access           `json:"access,omitempty"`
	MediaType       string            `json:"mediaType,omitempty"`
	Format          string            `json:"format,omitempty"`
	ExtraProperties map[string]string `json:"extraProperties,omitempty"`
}

type Access struct {
	URLType      string `json:"urlType"` // accessURL | downloadURL
	ServicePort  int    `json:"servicePort"`
	InternalPath string `json:"internalPath,omitempty"`
	ExternalPath string `json:"externalPath,omitempty"`
	Protocol     string `json:"protocol,omitempty"`
}

type ServiceMapping struct {
	DataService   *DataService  `json:"dataservice,omitempty"`
	Orchestration Orchestration `json:"orchestration"`
}

type DataService struct {
	Title           string            `json:"title,omitempty"`
	Description     string            `json:"description,omitempty"`
	ExtraProperties map[string]string `json:"extraProperties,omitempty"`
}

// 🔑 Important: dynamic spec preserved here
type Orchestration struct {
	Type    string               `json:"type"` // Deployment | Job | CronJob
	Trigger *Trigger             `json:"trigger,omitempty"`
	Spec    runtime.RawExtension `json:"spec,omitempty"`
}

type Trigger struct {
	Type string `json:"type,omitempty"` // http
	Path string `json:"path,omitempty"`
}

type ServiceConfigurationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ServiceConfiguration `json:"items"`
}

func LoadServiceConfiguration(
	ctx context.Context,
	name, namespace string,
) (*ServiceConfiguration, error) {

	obj, err := DynamicClient.
		Resource(ServiceConfigurationGVR).
		Namespace(namespace).
		Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	var svcConfig ServiceConfiguration

	err = runtime.DefaultUnstructuredConverter.
		FromUnstructured(obj.Object, &svcConfig)
	if err != nil {
		return nil, err
	}

	NormalizeRDF(&svcConfig)

	return &svcConfig, nil
}

func NormalizeRDF(sc *ServiceConfiguration) {
	if sc == nil {
		return
	}

	prefixes := sc.Spec.Prefixes
	if prefixes == nil {
		prefixes = map[string]string{}
	}

	// Default prefixes
	defaults := map[string]string{
		"dct":    "http://purl.org/dc/terms/",
		"dcat":   "http://www.w3.org/ns/dcat#",
		"foaf":   "http://xmlns.com/foaf/0.1/",
		"skos":   "http://www.w3.org/2004/02/skos/core#",
		"schema": "https://schema.org/",
		"fno":    "https://w3id.org/function/ontology#",
		"xsd":    "http://www.w3.org/2001/XMLSchema#",
	}

	base := ExternalServerURL() + DeploymentCatalog + "#"

	for k, v := range defaults {
		if _, exists := prefixes[k]; !exists {
			prefixes[k] = v
		}
	}

	// -------- INPUT MAPPING --------
	if sc.Spec.InputMapping != nil {
		expandedInput := make(map[string]InputMapping)

		for key, input := range sc.Spec.InputMapping {
			// Expand KEY (RDF predicate)
			newKey := util.ExpandValue(key, prefixes, base)
			expandedInput[newKey] = input
		}

		// Replace entire map
		sc.Spec.InputMapping = expandedInput
	}

	// -------- DATASETS --------
	for id, dataset := range sc.Spec.Datasets {
		dataset.ExtraProperties =
			util.ExpandRDFMap(dataset.ExtraProperties, prefixes, base)

		if dataset.Distribution != nil {
			dataset.Distribution.ExtraProperties =
				util.ExpandRDFMap(dataset.Distribution.ExtraProperties, prefixes, base)
		}

		sc.Spec.Datasets[id] = dataset
	}

	// -------- DATASERVICE --------
	if sc.Spec.ServiceMapping.DataService != nil {
		sc.Spec.ServiceMapping.DataService.ExtraProperties =
			util.ExpandRDFMap(
				sc.Spec.ServiceMapping.DataService.ExtraProperties,
				prefixes,
				base,
			)
	}
}
