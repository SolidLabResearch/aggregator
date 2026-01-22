package model

import "github.com/maartyman/rdfgo"

var DateTime = rdfgo.NewNamedNode("http://www.w3.org/2001/XMLSchema#dateTime")

func Agg(id string) rdfgo.INamedNode {
	return rdfgo.NewNamedNode(`https://spec.knows.idlab.ugent.be/aggregator-protocol/latest/#` + id)
}

func FnO(id string) rdfgo.INamedNode {
	return rdfgo.NewNamedNode(`https://w3id.org/function/ontology#` + id)
}
