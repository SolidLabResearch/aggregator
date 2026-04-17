export const HCP_SLICE_CONTEXT = {
    "kss": "https://kvasir.discover.ilabt.imec.be/vocab#",
    "faqir": "https://faqir.org/",
    "rdfs": "http://www.w3.org/2000/01/rdf-schema#"
};
export const HCP_SLICE_SCHEMA = `
type Query {
  patients: [faqir_Patient!]!
}

type faqir_Patient {
  faqir_podId: String!
  faqir_pt_hcp: [ID!]
}
  
type Subscription {
  onPatientToHCPRelationAdded: faqir_Patient!
    @trigger(type: INSERT, predicate: ["https://faqir.org/pt_hcp"], object: [])
}`;
export const HCP_QUERY = `
PREFIX faqir: <https://faqir.org/>
SELECT ?pod WHERE {
  ?patient faqir:podId ?pod ;
    faqir:pt_hcp ?doctor .
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

export const BAR_PROCEDURE_SLICE_CONTEXT = {
    "kss": "https://kvasir.discover.ilabt.imec.be/vocab#",
    "moveUp": "http://moveUp.care/",
    "snomed": "http://snomed.info/sct/",
    "foaf": "http://xmlns.com/foaf/0.1/",
    "dct": "http://purl.org/dc/terms/",
    "rdfs": "http://www.w3.org/2000/01/rdf-schema#"
};
export const BAR_PROCEDURE_SLICE_SCHEMA = `
type Query {
    bariatricProcedures: [moveUp_Procedure!]
}

type moveUp_Procedure @class(iri: "moveUp:Procedure") {
    id: ID!
    moveUp_code: Code!
        @predicate(iri: "moveUp:code")
    moveUp_performedDateTime: DateTime
        @predicate(iri: "moveUp:performedDateTime")
    moveUp_subject: ID!
        @predicate(iri: "moveUp:subject")
}

type Code @class(iri: "moveUp:Code") {
    id: ID!
    dct_description: String
    moveUp_coding: ID!
        @filter(if: "it=='snomed:442338001', 'snomed:427074001', 'snomed:7183004'")
}

type Subscription {
    onBariatricProcedureAdded: moveUp_Procedure!
}`;
export const BAR_PROCEDURE_QUERY = `
PREFIX moveUp: <http://moveUp.care/>
SELECT ?patient ?timestamp WHERE {
  ?proc a moveUp:Procedure ;
    moveUp:performedDateTime ?timestamp ;
    moveUp:subject ?patient .
    moveUp:code ?code .
}`;