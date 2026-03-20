export const HCP_SLICE_CONTEXT = {};
export const HCP_SLICE_SCHEMA = "";
export const HCP_QUERY = "";

export const WEIGHT_SLICE = "/Read-PoC2-Weight-Atomic-02";
export const WEIGHT_SLICE_CONTEXT = {
  "foaf": "https://sparontologies.github.io/foaf/current/",
  "kss": "https://kvasir.discover.ilabt.imec.be/vocab#",
  "openEHR": "https://ckm.openehr.org/ckm/",
  "rdfs": "https://www.w3.org/TR/rdf-schema/",
  "saref": "https://saref.etsi.org/core/",
  "schema": "http://schema.org/",
  "snomed": "https://browser.ihtsdotools.org/?perspective=full&conceptId1=404684003&edition=MAIN/2026-02-01&release=&languages=en",
  "ucum": "https://unitsofmeasure.org/",
  "moveUp": "https://moveup.care/",
  "faqir": "https://faqir.org/"
};

export const WEIGHT_SLICE_SCHEMA = `
type Query { 
  weightValues: [WeightValue!]! 
} 
  
type WeightProperty @class(iri: "saref:Property"){ 
  id: ID! 
  saref_isMeasuredIn: ID! @predicate(iri: "saref:isMeasuredIn") 
  rdfs_label: ID! @predicate(iri: "rdfs:label") @filter(if: "it=='snomed:27113001'") 
  ofSubject: ID! @predicate(iri: "saref:hasProperty", reverse: true) 
} 

type WeightValue @class(iri: "saref:PropertyValue") { 
  id: ID! 
  saref_isValueOfProperty: WeightProperty! @predicate(iri: "saref:isValueOfProperty") 
  saref_hasValue: Float! @predicate(iri: "saref:hasValue") 
  saref_hasTimestamp: DateTime! @predicate(iri: "saref:hasTimestamp") 
} 
  
type Subscription { 
  onWeightValueAdded: WeightValue! 
  onWeightValueDeleted: WeightValue! 
}`;

export const WEIGHT_QUERY = `
  SELECT ?value ?timestamp ?patient WHERE {
    ?weightValue a saref:PropertyValue ;
      saref:hasValue ?value
      saref:hasTimestamp ?timestamp ;
      saref:isValueOfProperty ?prop .
    ?patient saref:hasProperty ?prop .
  }
`;

export const PROCEDURE_SLICE = "/Read-PoC2-Procedure-BariatricAtomic-01";
export const PROCEDURE_SLICE_CONTEXT = {
  "foaf": "https://sparontologies.github.io/foaf/current/",
  "kss": "https://kvasir.discover.ilabt.imec.be/vocab#",
  "openEHR": "https://ckm.openehr.org/ckm/",
  "rdfs": "https://www.w3.org/TR/rdf-schema/",
  "saref": "https://saref.etsi.org/core/",
  "schema": "http://schema.org/",
  "snomed": "https://browser.ihtsdotools.org/?perspective=full&conceptId1=404684003&edition=MAIN/2026-02-01&release=&languages=en",
  "ucum": "https://unitsofmeasure.org/",
  "moveUp": "https://moveup.care/",
  "faqir": "https://faqir.org/"
};

export const PROCEDURE_SLICE_SCHEMA = `
type Query { 
  bariatricProcedures: [moveUp_Procedure!] 
} 

type moveUp_Procedure @class(iri: "moveUp:Procedure") { 
  id: ID! @predicate(iri: "moveUp:identity") 
  moveUp_code: ID! @predicate(iri: "moveUp:code") @filter(if: "it=in=('snomed:442338001', 'snomed:427074001')") 
  moveUp_performedDateTime: DateTime! @predicate(iri: "moveUp:performedDateTime") 
  moveUp_subject: ID! @predicate(iri: "moveUp:subject") 
}
  
type Subscription { 
  onBariatricProcedureAdded: moveUp_Procedure! 
}`;

export const PROCEDURE_QUERY = `
SELECT ?patient ?timestamp WHERE {
  ?proc a moveUp:Procedure ;
    moveUp:performedDateTime ?timestamp ;
    moveUp:subject ?patient .
}`;

export const QR_SLICE = "Read-PoC2-Questionnaire-Oxford-Atomic-02";
export const QR_SLICE_CONTEXT = {};
export const QR_SLICE_SCHEMA = "";
export const QR_QUERY = "";