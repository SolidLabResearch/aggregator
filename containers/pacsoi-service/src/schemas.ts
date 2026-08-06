export const HCP_SLICE_CONTEXT = {
    "kss": "https://kvasir.discover.ilabt.imec.be/vocab#",
    "faqir": "https://faqir.org/",
    "rdfs": "http://www.w3.org/2000/01/rdf-schema#"
};
export const HCP_SLICE_SCHEMA = `
type Query {
  patients: [faqir_patient!]!
}

type faqir_patient {
  faqir_podId: String!
  faqir_pt_hcp: [ID!]
}
  
type Subscription {
  onPatientToHCPRelationAdded: faqir_patient!
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
  "moveUp": "http://moveup.care/",
  "rdfs": "http://www.w3.org/2000/01/rdf-schema#",
  "saref": "https://saref.etsi.org/core/",
  "sosa": "http://www.w3.org/ns/sosa/"
};
export const WEIGHT_SLICE_SCHEMA = `
type Query {
  weightValues: [WeightValue!]!
}

type WeightProperty @class(iri: "saref:Property") {
  id: ID!
  ofSubject: ID! @predicate(iri: "saref:hasProperty", reverse: true)
}

type WeightValue @class(iri: "saref:PropertyValue") {
  id: ID!
  saref_isValueOfProperty: WeightProperty!
    @predicate(iri: "saref:isValueOfProperty")
  saref_hasValue: Float! @predicate(iri: "saref:hasValue")
  saref_hasTimestamp: DateTime! @predicate(iri: "saref:hasTimestamp")
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
  "dct": "http://purl.org/dc/terms/",
  "foaf": "http://xmlns.com/foaf/0.1/",
  "kss": "https://kvasir.discover.ilabt.imec.be/vocab#",
  "moveUp": "http://moveup.care/",
  "rdfs": "http://www.w3.org/2000/01/rdf-schema#",
  "snomed": "http://snomed.info/sct/"
};
export const BAR_PROCEDURE_SLICE_SCHEMA = `
type Query {
  bariatricProcedures: [moveUp_Procedure!]
}

type moveUp_Procedure @class(iri: "moveUp:Procedure") {
  id: ID!
  moveUp_code: Code! @predicate(iri: "moveUp:code")
  moveUp_performedDateTime: DateTime @predicate(iri: "moveUp:performedDateTime")
  moveUp_subject: ID! @predicate(iri: "moveUp:subject")
}

type Code @class(iri: "moveUp:Code") {
  id: ID!
  dct_description: String
  moveUp_coding: ID! @filter(if: "it=='snomed:442338001', 'snomed:427074001'")
}

type Subscription {
  onbariatricProcedureAdded: moveUp_Procedure!
}`;

export const KNEE_PROCEDURE_SLICE_CONTEXT = {
  "dct": "http://purl.org/dc/terms/",
  "foaf": "http://xmlns.com/foaf/0.1/",
  "kss": "https://kvasir.discover.ilabt.imec.be/vocab#",
  "moveUp": "http://moveup.care/",
  "rdfs": "http://www.w3.org/2000/01/rdf-schema#",
  "snomed": "http://snomed.info/sct/"
};
export const KNEE_PROCEDURE_SLICE_SCHEMA = `
type Query {
  kneeProcedures: [moveUp_Procedure!]
}

type moveUp_Procedure @class(iri: "moveUp:Procedure") {
  id: ID!
  moveUp_code: Code! @predicate(iri: "moveUp:code")
  moveUp_performedDateTime: DateTime @predicate(iri: "moveUp:performedDateTime")
  moveUp_subject: ID! @predicate(iri: "moveUp:subject")
}

type Code @class(iri: "moveUp:Code") {
  id: ID!
  dct_description: String
  moveUp_coding: ID!
    @filter(
      if: "it=='snomed:444463001', 'snomed:443682009', 'snomed:443681002', 'snomed:726419008', 'snomed:726418000', 'snomed:735261001', 'snomed:735262008'"
    )
}

type Subscription {
  onKneeProcedureAdded: moveUp_Procedure!
}`;
export const PROCEDURE_QUERY = `
PREFIX moveUp: <http://moveup.care/>
SELECT ?patient ?timestamp WHERE {
  ?proc a moveUp:Procedure ;
    moveUp:performedDateTime ?timestamp ;
    moveUp:subject ?patient ;
}`;

export const OXFORD_SLICE_CONTEXT = {
  "dct": "http://purl.org/dc/terms/",
  "faqir": "https://faqir.org/",
  "fhir": "http://hl7.org/fhir/",
  "foaf": "http://xmlns.com/foaf/0.1/",
  "kss": "https://kvasir.discover.ilabt.imec.be/vocab#",
  "moveUp": "http://moveup.care/",
  "openEHR": "http://openehr.org/",
  "rdfs": "http://www.w3.org/2000/01/rdf-schema#",
  "rml": "http://w3id.org/rml/",
  "saref": "https://saref.etsi.org/core/",
  "schema": "http://schema.org/",
  "snomed": "http://snomed.info/sct/",
  "sosa": "http://www.w3.org/ns/sosa/",
  "ucum": "https://unitsofmeasure.org/"
};
export const OXFORD_SLICE_SCHEMA = `
type Query {
  completedOxfordResponses: [CompletedOxfordResponse!]!
}

type CompletedOxfordResponse @class(iri: "moveUp:QuestionnaireResponse") {
  id: ID!
  moveUp_questionnaireResponseTimeStamp: DateTime!
    @predicate(iri: "moveUp:questionnaireResponseTimeStamp")
  moveUp_questionnaireResponseToQuestionnaire: moveUp_Questionnaire!
    @predicate(iri: "moveUp:questionnaireResponseToQuestionnaire")
  moveUp_questionnaireResponseBySubject: ID!
    @predicate(iri: "moveUp:questionnaireResponseBySubject")
  moveUp_questionnaireResponseHasAnswer: [moveUp_Answer!]!
    @predicate(iri: "moveUp:questionnaireResponseHasAnswer")
  moveUp_questionnaireResponseStatus: String!
    @predicate(iri: "moveUp:questionnaireResponseStatus")
    @filter(if: "it=='completed'")
}

type moveUp_Answer @class(iri: "moveUp:Answer") {
  id: ID!
  moveUp_answerValue: [BoxedLiteral] @predicate(iri: "moveUp:answerValue")
  moveUp_answerToQuestion: ID! @predicate(iri: "moveUp:answerToQuestion")
}

type moveUp_Questionnaire @class(iri: "moveUp:Questionnaire") {
  id: ID!
  moveUp_questionnaireLabel: String!
    @predicate(iri: "moveUp:questionnaireLabel")
    @filter(if: "it=='oxford'")
}

type Subscription {
  onCompletedOxfordResponseAdded: CompletedOxfordResponse!
}`;

export const OXFORD_QUERY = `
PREFIX moveUp: <http://moveup.care/>
SELECT ?res ?timestamp ?patient ?question ?value WHERE {
    ?res a moveUp:QuestionnaireResponse ;
        moveUp:questionnaireResponseTimeStamp ?timestamp ;
        moveUp:questionnaireResponseBySubject ?patient ;
        moveUp:questionnaireResponseHasAnswer ?answer .
    ?answer moveUp:answerValue ?value ;
        moveUp:answerToQuestion ?question
}`;