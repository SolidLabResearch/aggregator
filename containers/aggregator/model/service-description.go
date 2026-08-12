package model

import (
	"aggregator/util"
	"bytes"
	"strings"
	"time"

	"github.com/maartyman/rdfgo"
)

var DateTime = rdfgo.NewNamedNode("http://www.w3.org/2001/XMLSchema#dateTime")

func Agg(id string) rdfgo.INamedNode {
	return rdfgo.NewNamedNode(`https://w3id.org/aggregator#` + id)
}

func FnO(id string) rdfgo.INamedNode {
	return rdfgo.NewNamedNode(`https://w3id.org/function/ontology#` + id)
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
	Datasets map[string]rdfgo.Store
	Prefixes map[string]string
}

func (service *Service) InitDescription() error {
	description := ServiceDescription{
		Service:  rdfgo.NewStore(),
		Datasets: make(map[string]rdfgo.Store),
		Prefixes: service.Deployment.Definition.Prefixes,
	}

	svcNode := rdfgo.NewNamedNode(service.FullPath)

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
	if profile := service.Deployment.Definition.ServiceProfile; profile != nil {
		if profile.Title != "" {
			quad, err = rdfgo.NewQuad(svcNode, Dct("title"), rdfgo.NewStringLiteral(profile.Title, "en"), nil)
			if err != nil {
				return err
			}
			description.Service.AddQuad(quad)
		}
		if profile.Description != "" {
			quad, err = rdfgo.NewQuad(svcNode, Dct("description"), rdfgo.NewStringLiteral(profile.Description, "en"), nil)
			if err != nil {
				return err
			}
			description.Service.AddQuad(quad)
		}
		for predicate, value := range profile.ExtraProperties {
			quad, err = rdfgo.NewQuad(svcNode, rdfgo.NewNamedNode(predicate), util.StringToTerm(value), nil)
			if err != nil {
				return err
			}
			description.Service.AddQuad(quad)
		}
		for _, role := range profile.AccessRoles {
			quad, err = rdfgo.NewQuad(svcNode, Agg("availableRoles"), rdfgo.NewNamedNode(role.URI), nil)
			if err != nil {
				return err
			}
			description.Service.AddQuad(quad)
		}
	}

	// A profiled service conforms to its server-wide service profile. An
	// unprofiled service intentionally has no dct:conformsTo statement.
	if service.Deployment.Definition.ProfileURI != "" {
		quad, err = rdfgo.NewQuad(
			svcNode,
			Dct("conformsTo"),
			rdfgo.NewNamedNode(service.Deployment.Definition.ProfileURI),
			nil,
		)
		if err != nil {
			return err
		}
		description.Service.AddQuad(quad)
	}

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
	for _, endpoint := range service.Deployment.Definition.Endpoints {
		quad, err = rdfgo.NewQuad(
			svcNode, Dcat("endpointURL"),
			rdfgo.NewNamedNode(util.JoinPaths(service.FullPath, endpoint.Path)), nil,
		)
		if err != nil {
			return err
		}
		description.Service.AddQuad(quad)
	}

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

	// Record the deployment function that produced the service.
	quad, err = rdfgo.NewQuad(
		svcNode,
		Agg("deploymentFunction"),
		rdfgo.NewNamedNode(service.Deployment.Definition.URI),
		nil,
	)
	if err != nil {
		return err
	}
	description.Service.AddQuad(quad)

	// DATASETS
	for datasetID, dataset := range service.Deployment.Definition.Datasets {

		outputStore := rdfgo.NewStore()
		description.Datasets[datasetID] = outputStore

		// Dataset node
		datasetNode := rdfgo.NewNamedNode(service.FullPath + "#" + datasetID)

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

		if dataset.ProfileURI != "" {
			quad, err = rdfgo.NewQuad(
				datasetNode,
				Dct("conformsTo"),
				rdfgo.NewNamedNode(dataset.ProfileURI),
				nil,
			)
			if err != nil {
				return err
			}
			outputStore.AddQuad(quad)
		}

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
		if dataset.Title != "" {
			quad, err = rdfgo.NewQuad(
				datasetNode,
				Dct("title"),
				rdfgo.NewStringLiteral(dataset.Title, "en"),
				nil,
			)
			if err != nil {
				return err
			}
			outputStore.AddQuad(quad)
		}

		if dataset.Description != "" {
			quad, err = rdfgo.NewQuad(
				datasetNode,
				Dct("description"),
				rdfgo.NewStringLiteral(dataset.Description, "en"),
				nil,
			)
			if err != nil {
				return err
			}
			outputStore.AddQuad(quad)
		}

		// Extra RDF properties
		for predURI, val := range dataset.ExtraProperties {
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

		// DISTRIBUTIONS
		for distributionID, distribution := range dataset.Distributions {

			distNode := rdfgo.NewNamedNode(service.FullPath + "#" + datasetID + "-distribution-" + distributionID)

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
			if distribution.Title != "" {
				quad, err = rdfgo.NewQuad(
					distNode,
					Dct("title"),
					rdfgo.NewStringLiteral(distribution.Title, "en"),
					nil,
				)
				if err != nil {
					return err
				}
				outputStore.AddQuad(quad)
			}

			if distribution.Description != "" {
				quad, err = rdfgo.NewQuad(
					distNode,
					Dct("description"),
					rdfgo.NewStringLiteral(distribution.Description, "en"),
					nil,
				)
				if err != nil {
					return err
				}
				outputStore.AddQuad(quad)
			}
			if distribution.MediaType != "" {
				quad, err = rdfgo.NewQuad(distNode, Dcat("mediaType"), rdfgo.NewNamedNode("https://www.iana.org/assignments/media-types/"+distribution.MediaType), nil)
				if err != nil {
					return err
				}
				outputStore.AddQuad(quad)
			}
			if distribution.Format != "" {
				quad, err = rdfgo.NewQuad(distNode, Dct("format"), util.StringToTerm(distribution.Format), nil)
				if err != nil {
					return err
				}
				outputStore.AddQuad(quad)
			}

			// Access URL
			externalPath := distribution.Path
			if !strings.HasPrefix(externalPath, "/") {
				externalPath = "/" + externalPath
			}

			accessURL := service.FullPath + externalPath

			predicate := Dcat("accessURL")
			if distribution.URLType == "downloadURL" {
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
			for predURI, val := range distribution.ExtraProperties {
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

	// Write datasets
	for _, datasetStore := range description.Datasets {
		stream := datasetStore.Match(nil, nil, nil, nil)
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
