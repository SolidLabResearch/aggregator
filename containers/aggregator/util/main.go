package util

import (
	"fmt"
	"strings"

	"github.com/maartyman/rdfgo"
)

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

func ExpandValue(value string, prefixes map[string]string, base string) string {
	// Already full URI → leave as-is
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		return value
	}

	// Base prefix ":"
	if strings.HasPrefix(value, ":") {
		return base + strings.TrimPrefix(value, ":")
	}

	// Prefixed value (prefix:local)
	parts := strings.SplitN(value, ":", 2)
	if len(parts) == 2 {
		prefix, local := parts[0], parts[1]

		if uri, ok := prefixes[prefix]; ok {
			return uri + local
		}
	}

	// fallback → leave unchanged
	return value
}

func ExpandRDFMap(m map[string]string, prefixes map[string]string, base string) map[string]string {
	if m == nil {
		return m
	}

	expanded := make(map[string]string)

	for k, v := range m {
		newKey := ExpandValue(k, prefixes, base)
		newVal := ExpandValue(v, prefixes, base)
		expanded[newKey] = newVal
	}

	return expanded
}

func StringToTerm(val string) rdfgo.ITerm {
	if strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") {
		return rdfgo.NewNamedNode(val)
	}
	return rdfgo.NewStringLiteral(val, "")
}

func JoinPaths(base string, path string) string {
	if path == "" || path == "/" {
		return base
	}

	// ensure path starts with "/"
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	return base + path
}
