package model

import (
	"sort"
	"strings"

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

type Execution struct {
	URI            string
	Transformation *Transformation
	Params         map[string]rdfgo.ITerm
	Outputs        map[string]rdfgo.ITerm
}

type Transformation struct {
	Base          string                   `json:"base,omitempty"`
	URI           string                   `json:"uri"`
	Image         string                   `json:"image,omitempty"`
	FnO           string                   `json:"-"`
	Params        []string                 `json:"params,omitempty"`
	Outputs       []string                 `json:"outputs,omitempty"`
	InputMapping  map[string]string        `json:"inputMapping,omitempty"`
	OutputMapping map[string]OutputMapping `json:"outputMapping,omitempty"`
}

type OutputMapping struct {
	Port int32
	Path string
}

func (tf *Transformation) ParseTransformation() {
	tf.Params = []string{}
	tf.Outputs = []string{}

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

	// Get parameter predicates
	for listQuad := range store.Match(rdfgo.NewNamedNode(tf.URI), FnO("expects"), nil, nil) {
		for _, param := range RDFListToSlice(store, listQuad.GetObject()) {
			for predQuad := range store.Match(param, FnO("predicate"), nil, nil) {
				pred := predQuad.GetObject()
				tf.Params = append(tf.Params, strings.Trim(pred.ToString(), "<>"))
			}
		}
	}

	// Get output predicates
	for listQuad := range store.Match(rdfgo.NewNamedNode(tf.URI), FnO("returns"), nil, nil) {
		for _, output := range RDFListToSlice(store, listQuad.GetObject()) {
			for predQuad := range store.Match(output, FnO("predicate"), nil, nil) {
				pred := predQuad.GetObject()
				tf.Outputs = append(tf.Outputs, strings.Trim(pred.ToString(), "<>"))
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
