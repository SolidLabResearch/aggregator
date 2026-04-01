export const WEIGHT_SLICE = "/slices/Read-PoC2-Weight-Observations-05/query";
export const WEIGHT_SLICE_CONTEXT = {
  "foaf": "https://sparontologies.github.io/foaf/current/",
  "kss": "https://kvasir.discover.ilabt.imec.be/vocab#",
  "openEHR": "https://ckm.openehr.org/ckm/",
  "rdfs": "https://www.w3.org/TR/rdf-schema/",
  "saref": "https://saref.etsi.org/core/",
  "schema": "http://schema.org/",
  "snomed": "http://snomed.info/id/",
  "ucum": "https://unitsofmeasure.org/",
  "moveUp": "http://moveup.care/",
  "faqir": "https://faqir.org/"
};

export const WEIGHT_SLICE_SCHEMA = `
type Query { 
  weightValues: [WeightValue!]! 
} 
  
type WeightValue @class(iri: "saref:PropertyValue") { 
  id: ID! 
  saref_isValueOfProperty: WeightProperty! 
  saref_hasValue: Float! 
  saref_hasTimestamp: DateTime! 
} 
  
type WeightProperty @class(iri: "saref:Property") { 
  id: ID!
  ofSubject: ID! @predicate(iri: "saref:hasProperty", reverse: true) 
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

export const PROCEDURE_SLICE = "/slices/Read-PoC2-Patient-Procedure-05/query";
export const PROCEDURE_SLICE_CONTEXT = {
  "foaf": "https://sparontologies.github.io/foaf/current/",
  "kss": "https://kvasir.discover.ilabt.imec.be/vocab#",
  "openEHR": "https://ckm.openehr.org/ckm/",
  "rdfs": "https://www.w3.org/TR/rdf-schema/",
  "saref": "https://saref.etsi.org/core/",
  "schema": "http://schema.org/",
  "snomed": "http://snomed.info/id/",
  "ucum": "https://unitsofmeasure.org/",
  "moveUp": "http://moveup.care/",
  "faqir": "https://faqir.org/",
  "dcterms": "http://purl.org/dc/terms/"
};

export const PROCEDURE_SLICE_SCHEMA = `
type Query { 
  bariatricProceduresID: [moveUp_Procedure!] 
} 
  
type moveUp_Procedure { 
  id: ID! 
  moveUp_identity: moveUp_Identity 
  moveUp_code: moveUp_Code 
  moveUp_performedDateTime: DateTime! 
  moveUp_subject: ID!
}

type moveUp_Code {
  id: ID!
  moveUp_coding: ID! @predicate(iri: "moveUp:coding") @filter(if: "it=in=('snomed:442338001', 'snomed:427074001')")
}
  
type moveUp_Identity { 
  id: ID! 
  moveUp_value: String! 
  moveUp_system: ID! 
} 
  
type Subscription { 
  onbariatricprocedureAdded: moveUp_Procedure! 
}`;

export const PROCEDURE_QUERY = `
PREFIX moveUp: <http://moveup.care/>
SELECT ?patient ?timestamp WHERE {
  ?proc a moveUp:Procedure ;
    moveUp:performedDateTime ?timestamp ;
    moveUp:subject ?patient .
}`;