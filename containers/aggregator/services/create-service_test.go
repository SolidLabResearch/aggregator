package services

import (
	"reflect"
	"testing"
)

func TestExtractQueryAndSources_HappyPath(t *testing.T) {
	desc := `@prefix config: <http://localhost:5000/config#> .
@prefix fno: <https://w3id.org/function/ontology#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
_:execution a fno:Execution ;
    fno:executes config:SPARQLEvaluation ;
    config:sources ( "http://localhost:3000/alice/profile/card"^^xsd:string ) ;
    config:queryString "SELECT * WHERE { ?s ?p ?o }" .`

	q, s, err := extractQueryAndSources(desc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if q != "SELECT * WHERE { ?s ?p ?o }" {
		t.Fatalf("unexpected query: %s", q)
	}

	exp := []string{"http://localhost:3000/alice/profile/card"}
	if !reflect.DeepEqual(s, exp) {
		t.Fatalf("unexpected sources: %v", s)
	}
}

func TestExtractQueryAndSources_DifferentNamespaceAndMultipleSources(t *testing.T) {
	desc := `@prefix cfg: <http://example.org/config#> .
@prefix fno: <https://w3id.org/function/ontology#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
_:e a fno:Execution ;
    fno:executes cfg:SPARQLEvaluation ;
    cfg:sources ( "http://a.example" "http://b.example" ) ;
    cfg:queryString "ASK WHERE { ?s ?p ?o }" .`

	q, s, err := extractQueryAndSources(desc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if q != "ASK WHERE { ?s ?p ?o }" {
		t.Fatalf("unexpected query: %s", q)
	}

	exp := []string{"http://a.example", "http://b.example"}
	if !reflect.DeepEqual(s, exp) {
		t.Fatalf("unexpected sources: %v", s)
	}
}

func TestExtractQueryAndSources_MissingQuery(t *testing.T) {
	desc := `@prefix config: <http://localhost:5000/config#> .
@prefix fno: <https://w3id.org/function/ontology#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
_:execution a fno:Execution ;
    fno:executes config:SPARQLEvaluation ;
    config:sources ( "http://localhost:3000/alice/profile/card"^^xsd:string ) .`

	_, _, err := extractQueryAndSources(desc)
	if err == nil {
		t.Fatalf("expected error due to missing queryString, got nil")
	}
}

func TestExtractQueryAndSources_MissingSources(t *testing.T) {
	desc := `@prefix config: <http://localhost:5000/config#> .
@prefix fno: <https://w3id.org/function/ontology#> .
_:execution a fno:Execution ;
    fno:executes config:SPARQLEvaluation ;
    config:queryString "SELECT * WHERE { ?s ?p ?o }" .`

	_, _, err := extractQueryAndSources(desc)
	if err == nil {
		t.Fatalf("expected error due to missing sources, got nil")
	}
}
