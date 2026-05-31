package model

import (
	"aggregator/util"
	"bytes"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/maartyman/rdfgo"
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

func Dct(id string) rdfgo.INamedNode {
	return rdfgo.NewNamedNode(`http://purl.org/dc/terms/` + id)
}

func Prov(id string) rdfgo.INamedNode {
	return rdfgo.NewNamedNode(`http://www.w3.org/ns/prov#` + id)
}

type ServiceDescription struct {
	Service  rdfgo.Store
	Outputs  map[string]rdfgo.Store
	Prefixes map[string]string
}

func (service *Service) InitDescription() error {
	description := ServiceDescription{
		Service:  rdfgo.NewStore(),
		Outputs:  make(map[string]rdfgo.Store),
		Prefixes: service.Configuration.Spec.Prefixes,
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
	for param, value := range service.Application.Bindings {
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
	for pred, output := range service.Configuration.Spec.OutputMapping {

		id := uuid.New().String()
		outputStore := rdfgo.NewStore()
		description.Outputs[pred] = outputStore

		// Dataset node
		datasetNode := rdfgo.NewNamedNode(service.FullPath + "#" + id + "Dataset")

		quad, err := rdfgo.NewQuad(
			datasetNode,
			rdfgo.IRI.RDF.Type,
			Dcat("Dataset"),
			nil,
		)
		if err != nil {
			return err
		}
		outputStore.AddQuad(quad)

		// Service serves dataset
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

		// DATASET METADATA
		if output.Dataset != nil {

			if output.Dataset.Title != "" {
				quad, err = rdfgo.NewQuad(
					datasetNode,
					Dct("title"),
					rdfgo.NewStringLiteral(output.Dataset.Title, "en"),
					nil,
				)
				if err != nil {
					return err
				}
				outputStore.AddQuad(quad)
			}

			if output.Dataset.Description != "" {
				quad, err = rdfgo.NewQuad(
					datasetNode,
					Dct("description"),
					rdfgo.NewStringLiteral(output.Dataset.Description, "en"),
					nil,
				)
				if err != nil {
					return err
				}
				outputStore.AddQuad(quad)
			}

			// Extra RDF properties
			for predURI, val := range output.Dataset.ExtraProperties {
				quad, err = rdfgo.NewQuad(
					datasetNode,
					rdfgo.NewNamedNode(predURI),
					util.StringToTerm(val),
					nil,
				)
				if err != nil {
					return err
				}
				outputStore.AddQuad(quad)
			}
		}

		// DISTRIBUTION
		if output.Distribution != nil && output.Distribution.Access != nil {

			distNode := rdfgo.NewNamedNode(service.FullPath + "#" + id + "Distribution")

			// rdf:type
			quad, err = rdfgo.NewQuad(
				distNode,
				rdfgo.IRI.RDF.Type,
				Dcat("Distribution"),
				nil,
			)
			if err != nil {
				return err
			}
			outputStore.AddQuad(quad)

			// link dataset → distribution
			quad, err = rdfgo.NewQuad(
				datasetNode,
				Dcat("distribution"),
				distNode,
				nil,
			)
			if err != nil {
				return err
			}
			outputStore.AddQuad(quad)

			// Distribution metadata
			if output.Distribution.Title != "" {
				quad, err = rdfgo.NewQuad(
					distNode,
					Dct("title"),
					rdfgo.NewStringLiteral(output.Distribution.Title, "en"),
					nil,
				)
				if err != nil {
					return err
				}
				outputStore.AddQuad(quad)
			}

			if output.Distribution.Description != "" {
				quad, err = rdfgo.NewQuad(
					distNode,
					Dct("description"),
					rdfgo.NewStringLiteral(output.Distribution.Description, "en"),
					nil,
				)
				if err != nil {
					return err
				}
				outputStore.AddQuad(quad)
			}

			// Access URL
			access := output.Distribution.Access

			externalPath := access.ExternalPath
			if !strings.HasPrefix(externalPath, "/") {
				externalPath = "/" + externalPath
			}

			accessURL := service.FullPath + externalPath

			predicate := Dcat("accessURL")
			if access.URLType == "downloadURL" {
				predicate = Dcat("downloadURL")
			}

			quad, err = rdfgo.NewQuad(
				distNode,
				predicate,
				rdfgo.NewNamedNode(accessURL),
				nil,
			)
			if err != nil {
				return err
			}
			outputStore.AddQuad(quad)

			// Link to DataService
			quad, err = rdfgo.NewQuad(
				distNode,
				Dcat("accessService"),
				svcNode,
				nil,
			)
			if err != nil {
				return err
			}
			outputStore.AddQuad(quad)

			// Distribution extra RDF
			for predURI, val := range output.Distribution.ExtraProperties {
				quad, err = rdfgo.NewQuad(
					distNode,
					rdfgo.NewNamedNode(predURI),
					util.StringToTerm(val),
					nil,
				)
				if err != nil {
					return err
				}
				outputStore.AddQuad(quad)
			}
		}
	}

	service.Description = description

	return nil
}

func (description *ServiceDescription) FnORepresentation() ([]byte, error) {
	// serialize to turtle
	var buf bytes.Buffer

	// Write service description
	stream := description.Service.Match(nil, nil, nil, nil)
	_, err := rdfgo.Write(stream, &buf, rdfgo.WriterOptions{
		Format:   "turtle",
		Prefixes: description.Prefixes,
	})
	if err != nil {
		return nil, err
	}

	// Write outputs
	for _, outputStore := range description.Outputs {
		stream := outputStore.Match(nil, nil, nil, nil)
		_, err := rdfgo.Write(stream, &buf, rdfgo.WriterOptions{
			Format:   "turtle",
			Prefixes: description.Prefixes,
		})
		if err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}
