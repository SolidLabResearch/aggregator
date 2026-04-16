export const HCP_SLICE_CONTEXT = {
    "kss": "https://kvasir.discover.ilabt.imec.be/vocab#",
    "faqir": "https://faqir.org/",
    "rdfs": "http://www.w3.org/2000/01/rdf-schema#"
};
export const HCP_SLICE_SCHEMA = `
type Query {
  patients: [faqir_Patient!]!
}

type Mutation {
  add(patient: [PatientInput!]!): ID!
}

type PatientInput @class(iri: "faqir:Patient") {
  id: ID!
  faqir_podId: String!
}

type faqir_Patient {
  id: ID!
  faqir_podId: String!
}
  
type Subscription {
  onPatientAdded: faqir_Patient!
}`;
export const HCP_QUERY = `
PREFIX faqir: <https://faqir.org/>
SELECT ?id ?pod WHERE {
  ?id faqir:podId ?pod .
}`;

export const WEIGHT_SLICE_CONTEXT = {
    "kss": "https://kvasir.discover.ilabt.imec.be/vocab#",
    "moveUp": "http://moveUp.care/",
    "sosa": "http://www.w3.org/ns/sosa/",
    "saref": "https://saref.etsi.org/core/",
    "rdfs": "http://www.w3.org/2000/01/rdf-schema#"
};
export const WEIGHT_SLICE_SCHEMA = `
type Query { 
    weightValues: [WeightValue!]!
} 

type WeightProperty @class(iri: "saref:Property"){
    id: ID!
    ofSubject: ID!
        @predicate(iri: "saref:hasProperty", reverse: true)  
}

type WeightValue @class(iri: "saref:PropertyValue") {
    id: ID!
    saref_isValueOfProperty: WeightProperty!
        @predicate(iri: "saref:isValueOfProperty")    
    saref_hasValue: Float!
        @predicate(iri: "saref:hasValue")
    saref_hasTimestamp: DateTime!
        @predicate(iri: "saref:hasTimestamp")
}

type Subscription {
    onWeightValueAdded: WeightValue!
}`;
export const WEIGHT_QUERY = `
  PREFIX saref: <https://saref.etsi.org/core/>
  SELECT ?value ?timestamp ?patient WHERE {
    ?weightValue a saref:PropertyValue ;
      saref:hasValue ?value ;
      saref:hasTimestamp ?timestamp ;
      saref:isValueOfProperty ?prop .
    ?patient saref:hasProperty ?prop .
  }
`;

export const PROCEDURE_SLICE_CONTEXT = {
    "kss": "https://kvasir.discover.ilabt.imec.be/vocab#",
    "moveUp": "http://moveUp.care/",
    "snomed": "http://snomed.info/sct/",
    "foaf": "http://xmlns.com/foaf/0.1/",
    "dct": "http://purl.org/dc/terms/",
    "rdfs": "http://www.w3.org/2000/01/rdf-schema#"
};
export const PROCEDURE_SLICE_SCHEMA = `
type Query {
    procedures: [Procedure!]
}

type Procedure @class(iri: "moveUp:Procedure") {
    id: ID!
    moveUp_code: Code!
        @predicate(iri: "moveUp:code")
    moveUp_performedDateTime: DateTime
        @predicate(iri: "moveUp:performedDateTime")
    moveUp_subject: ID!
        @predicate(iri: "moveUp:subject")
}

type Code @class(iri: "moveUp:Code") {
    dct_description: String
    moveUp_coding: ID!
}

type Subscription {
    onProcedureAdded: Procedure!
}`;
export const PROCEDURE_QUERY = `
PREFIX moveUp: <http://moveUp.care/>
SELECT ?patient ?timestamp WHERE {
  ?proc a moveUp:Procedure ;
    moveUp:performedDateTime ?timestamp ;
    moveUp:subject ?patient .
}`;