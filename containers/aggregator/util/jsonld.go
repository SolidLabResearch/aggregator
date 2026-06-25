package util

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/piprate/json-gold/ld"
)

// AggregatorContextURL is the JSON-LD context every JSON-LD request must include.
const AggregatorContextURL = "https://w3id.org/aggregator/contexts/aggregator.jsonld"

// validateMandatoryContext checks that the aggregator context is present in @context,
// either as the sole value or as one entry of a context array. Other contexts
// (e.g. for parameter predicates) may sit alongside it.
func validateMandatoryContext(doc map[string]interface{}) error {
	ctx, ok := doc["@context"]
	if !ok {
		return fmt.Errorf("missing @context: must include %s", AggregatorContextURL)
	}

	switch v := ctx.(type) {
	case string:
		if v == AggregatorContextURL {
			return nil
		}
	case []interface{}:
		for _, entry := range v {
			if s, ok := entry.(string); ok && s == AggregatorContextURL {
				return nil
			}
		}
	}

	return fmt.Errorf("@context must include the mandatory aggregator context %s", AggregatorContextURL)
}

// jsonLDDocumentLoader caches dereferenced contexts so the mandatory aggregator
// context isn't fetched over the network on every request.
var jsonLDDocumentLoader = ld.NewCachingDocumentLoader(ld.NewDefaultDocumentLoader(nil))

// jsonLDToNQuads validates and converts a JSON-LD request body into N-Quads,
// so it can be fed through the same RDF pipeline as Turtle requests.
func JsonLDToNQuads(body []byte) (string, error) {
	var doc map[string]interface{}
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", fmt.Errorf("invalid JSON-LD: %w", err)
	}

	if err := validateMandatoryContext(doc); err != nil {
		return "", err
	}

	proc := ld.NewJsonLdProcessor()
	options := ld.NewJsonLdOptions("")
	options.Format = "application/n-quads"
	options.DocumentLoader = jsonLDDocumentLoader

	rdf, err := proc.ToRDF(doc, options)
	if err != nil {
		return "", fmt.Errorf("failed to expand JSON-LD to RDF: %w", err)
	}

	nquads, ok := rdf.(string)
	if !ok {
		return "", errors.New("unexpected output from JSON-LD processor")
	}

	return nquads, nil
}
