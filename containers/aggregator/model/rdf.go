package model

import (
	"bytes"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/maartyman/rdfgo"
	"github.com/sirupsen/logrus"
)

var DateTime = rdfgo.NewNamedNode("http://www.w3.org/2001/XMLSchema#dateTime")

func Agg(id string) rdfgo.INamedNode {
	return rdfgo.NewNamedNode(`https://spec.knows.idlab.ugent.be/aggregator-protocol/latest/#` + id)
}

func FnO(id string) rdfgo.INamedNode {
	return rdfgo.NewNamedNode(`https://w3id.org/function/ontology#` + id)
}

func FnOC(id string) rdfgo.INamedNode {
	return rdfgo.NewNamedNode(`https://w3id.org/function/vocabulary/composition#` + id)
}

func Dcat(id string) rdfgo.INamedNode {
	return rdfgo.NewNamedNode(`http://www.w3.org/ns/dcat#` + id)
}

func Prov(id string) rdfgo.INamedNode {
	return rdfgo.NewNamedNode(`http://www.w3.org/ns/prov#` + id)
}

type Application struct {
	Transformation *Transformation
	Params         map[string]rdfgo.ITerm
}

type Transformation struct {
	Base          string                   `json:"base,omitempty"`
	URI           string                   `json:"uri"`
	Image         string                   `json:"image,omitempty"`
	FnO           string                   `json:"-"`
	Params        map[string]string        `json:"params,omitempty"`
	Outputs       map[string]string        `json:"outputs,omitempty"`
	Predicates    map[string]string        `json:"predicates,omitempty"`
	InputMapping  map[string]string        `json:"inputMapping,omitempty"`
	OutputMapping map[string]OutputMapping `json:"outputMapping,omitempty"`
}

type OutputMapping struct {
	Port int32
	Path string
}

type ServiceDescription struct {
	Service rdfgo.Store
	Outputs map[string]rdfgo.Store
}

func (tf *Transformation) ParseTransformation() {
	tf.Params = map[string]string{}
	tf.Outputs = map[string]string{}
	tf.Predicates = map[string]string{}

	quadStream, errChan := rdfgo.Parse(
		strings.NewReader(tf.FnO),
		rdfgo.ParserOptions{
			Format:  "text/turtle",
			BaseIRI: ExternalServerURL() + TransformationCatalog + "#",
		},
	)

	go func() {
		for parseErr := range errChan {
			if parseErr != nil {
				logrus.WithError(parseErr).Warnf("Error parsing FnO description for <%s>", tf.URI)
			}
		}
	}()

	store := rdfgo.NewStore()
	store.Import(quadStream)

	// Get parameters
	for listQuad := range store.Match(rdfgo.NewNamedNode(tf.URI), FnO("expects"), nil, nil) {
		for _, param := range RDFListToSlice(store, listQuad.GetObject()) {
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
		for _, output := range RDFListToSlice(store, listQuad.GetObject()) {
			for predQuad := range store.Match(output, FnO("predicate"), nil, nil) {
				predUri := strings.Trim(predQuad.GetObject().ToString(), "<>")
				outputUri := strings.Trim(output.ToString(), "<>")
				tf.Predicates[predUri] = outputUri
				tf.Outputs[outputUri] = predUri
			}
		}
	}
}

func (tf *Transformation) Ports() []int32 {
	unique := make(map[int32]struct{})

	for _, out := range tf.OutputMapping {
		unique[out.Port] = struct{}{}
	}

	ports := make([]int32, 0, len(unique))
	for p := range unique {
		ports = append(ports, p)
	}

	sort.Slice(ports, func(i, j int) bool {
		return ports[i] < ports[j]
	})

	return ports
}

// Utils

func RDFListToSlice(store rdfgo.Store, headNode rdfgo.ITerm) []rdfgo.ITerm {
	var elements []rdfgo.ITerm
	listNode := headNode

	for !listNode.Equals(rdfgo.IRI.RDF.Nil) {
		// Get the first element
		firstQuads := store.Match(listNode, rdfgo.IRI.RDF.First, nil, nil)
		var first rdfgo.ITerm
		for fq := range firstQuads {
			first = fq.GetObject()
			break
		}

		if first != nil {
			elements = append(elements, first)
		}

		// Move to the rest of the list
		restQuads := store.Match(listNode, rdfgo.IRI.RDF.Rest, nil, nil)
		listNode = rdfgo.IRI.RDF.Nil // default to nil
		for rq := range restQuads {
			listNode = rq.GetObject()
			break
		}
	}

	return elements
}

func (service *Service) InitDescription() error {
	description := ServiceDescription{
		Service: rdfgo.NewStore(),
		Outputs: make(map[string]rdfgo.Store),
	}

	svcNode := rdfgo.NewNamedNode(service.FullPath + "#" + "service")

	// service is a agg:Service
	quad, err := rdfgo.NewQuad(
		svcNode,
		rdfgo.IRI.RDF.Type,
		Agg("Service"),
		nil,
	)
	if err != nil {
		return err
	}
	description.Service.AddQuad(quad)

	// service is a dcat:DataService
	quad, err = rdfgo.NewQuad(
		svcNode,
		rdfgo.IRI.RDF.Type,
		Dcat("DataService"),
		nil,
	)
	if err != nil {
		return err
	}
	description.Service.AddQuad(quad)

	// service is a prov:SoftwareAgent
	quad, err = rdfgo.NewQuad(
		svcNode,
		rdfgo.IRI.RDF.Type,
		Prov("SoftwareAgent"),
		nil,
	)
	if err != nil {
		return err
	}
	description.Service.AddQuad(quad)

	// SERVICE DETAILS
	// service status
	quad, err = rdfgo.NewQuad(
		svcNode,
		Agg("status"),
		rdfgo.NewStringLiteral(service.Status(), "en"),
		nil,
	)
	if err != nil {
		return err
	}
	description.Service.AddQuad(quad)

	// service createdAt
	quad, err = rdfgo.NewQuad(
		svcNode,
		Agg("createdAt"),
		rdfgo.NewLiteral(service.CreatedAt.Format(time.RFC3339), "", DateTime),
		nil,
	)
	if err != nil {
		return err
	}
	description.Service.AddQuad(quad)

	// service performs
	quad, err = rdfgo.NewQuad(
		svcNode,
		Agg("performs"),
		rdfgo.NewNamedNode(service.Application.Transformation.URI),
		nil,
	)
	if err != nil {
		return err
	}
	description.Service.AddQuad(quad)

	// service applies
	appNode := rdfgo.NewBlankNode(uuid.New().String())
	quad, err = rdfgo.NewQuad(
		svcNode,
		Agg("applies"),
		appNode,
		nil,
	)
	if err != nil {
		return err
	}
	description.Service.AddQuad(quad)

	// APPLICATION DETAILS
	// application applies transformation
	quad, err = rdfgo.NewQuad(
		appNode,
		FnOC("applies"),
		rdfgo.NewNamedNode(service.Application.Transformation.URI),
		nil,
	)
	if err != nil {
		return err
	}
	description.Service.AddQuad(quad)

	// application binds parameters
	for param, value := range service.Application.Params {
		bindingNode := rdfgo.NewBlankNode(uuid.New().String())
		quad, err = rdfgo.NewQuad(
			appNode,
			FnOC("parameterBinding"),
			bindingNode,
			nil,
		)
		if err != nil {
			return err
		}
		description.Service.AddQuad(quad)

		// application parameterBinding boundParameter
		quad, err = rdfgo.NewQuad(
			bindingNode,
			FnOC("boundParameter"),
			rdfgo.NewNamedNode(param),
			nil,
		)
		if err != nil {
			return err
		}
		description.Service.AddQuad(quad)

		// application parameterBinding boundToTerm
		quad, err = rdfgo.NewQuad(
			bindingNode,
			FnOC("boundToTerm"),
			value,
			nil,
		)
		if err != nil {
			return err
		}
		description.Service.AddQuad(quad)
	}

	// OUTPUTS
	for pred := range service.Application.Transformation.OutputMapping {
		// Create a store for the output
		outputStore := rdfgo.NewStore()
		description.Outputs[pred] = outputStore
		datasetNode := rdfgo.NewNamedNode(service.FullPath + "#" + pred + "Dataset")

		// output is a dcat:Dataset
		quad, err = rdfgo.NewQuad(
			datasetNode,
			rdfgo.IRI.RDF.Type,
			Dcat("Dataset"),
			nil,
		)
		if err != nil {
			return err
		}
		outputStore.AddQuad(quad)

		// output is serverd by a dcat:DataService
		quad, err = rdfgo.NewQuad(
			svcNode,
			Dcat("servesDataset"),
			datasetNode,
			nil,
		)
		if err != nil {
			return err
		}
		outputStore.AddQuad(quad)

		// OUTPUT DISTRIBUTION
		distributionNode := rdfgo.NewNamedNode(service.FullPath + "#" + pred + "Distribution")

		// output has a dcat:Distribution
		quad, err = rdfgo.NewQuad(
			distributionNode,
			rdfgo.IRI.RDF.Type,
			Dcat("Distribution"),
			nil,
		)
		if err != nil {
			return err
		}
		outputStore.AddQuad(quad)

		quad, err = rdfgo.NewQuad(
			datasetNode,
			Dcat("distribution"),
			distributionNode,
			nil,
		)
		if err != nil {
			return err
		}
		outputStore.AddQuad(quad)

		// distribution has a dcat:accessURL
		quad, err = rdfgo.NewQuad(
			distributionNode,
			Dcat("accessURL"),
			rdfgo.NewNamedNode(service.FullPath+"/"+pred),
			nil,
		)
		if err != nil {
			return err
		}
		outputStore.AddQuad(quad)

		// distribution has a dcat:DataService
		quad, err = rdfgo.NewQuad(
			distributionNode,
			Dcat("accessService"),
			svcNode,
			nil,
		)
		if err != nil {
			return err
		}
		outputStore.AddQuad(quad)
	}

	service.Description = description

	return nil
}

func (description *ServiceDescription) FnORepresentation() ([]byte, error) {
	// serialize to turtle
	var buf bytes.Buffer

	// Write service description
	stream := description.Service.Match(nil, nil, nil, nil)
	_, err := rdfgo.Write(stream, &buf, rdfgo.WriterOptions{Format: "turtle"})
	if err != nil {
		return nil, err
	}

	// Write outputs
	for _, outputStore := range description.Outputs {
		stream := outputStore.Match(nil, nil, nil, nil)
		_, err := rdfgo.Write(stream, &buf, rdfgo.WriterOptions{Format: "turtle"})
		if err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}
