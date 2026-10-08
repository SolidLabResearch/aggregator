/**
 * GraphQL-LD schemas, JSON-LD contexts, and SPARQL queries used by query.ts.
 *
 * The schema describes each remote slice to the query engine; the paired
 * context expands its compact field names into RDF predicates. The SELECT
 * variable names are an internal API: query.ts reads these exact binding names.
 */
export const PATIENT_SLICE_CONTEXT = {
  "brbdr": "https://www.sciensano.be/en/",
  "dcterms": "http://purl.org/dc/terms/",
  "ePPO": "https://bioportal.bioontology.org/ontologies/E-PPO",
  "faqir": "https://data.faqir.org/",
  "fhir": "http://hl7.org/fhir/",
  "foaf": "http://xmlns.com/foaf/0.1/",
  "kss": "https://kvasir.discover.ilabt.imec.be/vocab#",
  "moveup": "https://moveup.care/",
  "omop": "https://www.ohdsi.org/data-standardization/",
  "openEHR": "http://openehr.org/",
  "owl": "http://www.w3.org/2002/07/owl#",
  "phro": "https://ns.faqir.org/phr-o#",
  "prov": "http://www.w3.org/ns/prov#",
  "qo": "https://ns.faqir.org/q-o#",
  "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
  "rdfs": "http://www.w3.org/2000/01/rdf-schema#",
  "rml": "http://w3id.org/rml/",
  "saref": "https://saref.etsi.org/core/",
  "schema": "http://schema.org/",
  "snomed": "http://snomed.info/sct/",
  "sosa": "http://www.w3.org/ns/sosa/",
  "sphn": "https://sphn.ch/",
  "s4ehaw": "https://saref.etsi.org/saref4ehaw",
  "tmp": "https://www2.telemonitoring-prescription.com/openapi#",
  "ucum": "https://unitsofmeasure.org/"
};
export const PATIENT_SLICE_SCHEMA = `
type Query {
    patients: [foaf_Person!]!
}

type foaf_Person {
    id: ID!
    schema_birthDate: [s4ehaw_dob!]
    openEHR_sex_assigned_at_birth: [openEHR_Sex_assigned_at_birth!]
    # patient has zero or more pseudo identifiers
    sphn_hasIdentifier: [sphn_SubjectPseudoIdentifier!]
}

# Added pseudo identifier type
type sphn_SubjectPseudoIdentifier {
    id: ID!
    saref_hasValue: String!
    saref_hasTimestamp: DateTime!
    omop_valid_start_date: DateTime!
    fhir_issuer: ID!
}

type s4ehaw_dob {
    id: ID!
    saref_hasValue: DateTime!
    saref_hasTimestamp: DateTime!
}

type openEHR_Sex_assigned_at_birth {
    id: ID!
    saref_hasValue: ID!
    saref_hasTimestamp: DateTime!
}

type Subscription {
    onPatientAdded: foaf_Person!
    onPatientRemoved: foaf_Person!
}`;
export const PATIENT_QUERY = `
  PREFIX foaf: <http://xmlns.com/foaf/0.1/>
  PREFIX sphn: <https://sphn.ch/>
  PREFIX saref: <https://saref.etsi.org/core/>
  PREFIX fhir: <http://hl7.org/fhir/>
  SELECT ?patient ?idValue ?issuer WHERE {
    ?patient a foaf:Person ;
      sphn:hasIdentifier ?identifier .
    ?identifier saref:hasValue ?idValue ;
      fhir:issuer ?issuer .
  }
`;

export const WEIGHT_SLICE_CONTEXT = {
  "brbdr": "https://www.sciensano.be/en/",
  "dcterms": "http://purl.org/dc/terms/",
  "ePPO": "https://bioportal.bioontology.org/ontologies/E-PPO",
  "faqir": "https://data.faqir.org/",
  "fhir": "http://hl7.org/fhir/",
  "foaf": "http://xmlns.com/foaf/0.1/",
  "kss": "https://kvasir.discover.ilabt.imec.be/vocab#",
  "moveup": "https://moveup.care/",
  "omop": "https://www.ohdsi.org/data-standardization/",
  "openEHR": "http://openehr.org/",
  "owl": "http://www.w3.org/2002/07/owl#",
  "phro": "https://ns.faqir.org/phr-o#",
  "prov": "http://www.w3.org/ns/prov#",
  "qo": "https://ns.faqir.org/q-o#",
  "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
  "rdfs": "http://www.w3.org/2000/01/rdf-schema#",
  "rml": "http://w3id.org/rml/",
  "saref": "https://saref.etsi.org/core/",
  "schema": "http://schema.org/",
  "snomed": "http://snomed.info/sct/",
  "sosa": "http://www.w3.org/ns/sosa/",
  "sphn": "https://sphn.ch/",
  "s4ehaw": "https://saref.etsi.org/saref4ehaw",
  "tmp": "https://www2.telemonitoring-prescription.com/openapi#",
  "ucum": "https://unitsofmeasure.org/"
};
export const WEIGHT_SLICE_SCHEMA = `
type Query {
  weightObservations: [WeightObservation!]!
}

type WeightObservation @class(iri: "sosa:Observation") {
  id: ID!
  sosa_hasFeatureOfInterest: ID!
  sosa_hasResult: WeightValue!
  sosa_observedProperty: ID! @filter(if: "it=='http://snomed.info/id/27113001'")
  saref_isMeasuredIn: ID
}

type WeightValue @class(iri: "saref:PropertyValue") {
  id: ID!
  saref_isValueOfProperty: ID!
    @filter(if: "it=='http://snomed.info/id/27113001'")
  saref_hasValue: Float!
  saref_hasTimestamp: DateTime!
  prov_hadPrimarySource: ID
  prov_wasGeneratedBy: prov_Activity
}

type prov_Activity {
  id: ID!
  rdfs_label: String!
  rdfs_comment: String
  owl_versionInfo: String
  prov_atTime: DateTime!
  prov_wasAssociatedWith: ID
}

type Subscription {
  onObservationAdded: WeightObservation!
}`;

export const WEIGHT_QUERY = `
  PREFIX saref: <https://saref.etsi.org/core/>
  PREFIX sosa: <http://www.w3.org/ns/sosa/>
  SELECT ?observation ?value ?timestamp ?patient WHERE {
    ?observation a sosa:Observation ;
      sosa:hasFeatureOfInterest ?patient ;
      sosa:hasResult ?weightValue .
    ?weightValue a saref:PropertyValue ;
      saref:hasValue ?value ;
      saref:hasTimestamp ?timestamp .
  }
`;

export const BAR_PROCEDURE_SLICE_CONTEXT = {
    "brbdr": "https://www.sciensano.be/en/",
    "dcterms": "http://purl.org/dc/terms/",
    "ePPO": "https://bioportal.bioontology.org/ontologies/E-PPO",
    "faqir": "https://data.faqir.org/",
    "fhir": "http://hl7.org/fhir/",
    "foaf": "http://xmlns.com/foaf/0.1/",
    "kss": "https://kvasir.discover.ilabt.imec.be/vocab#",
    "moveup": "https://moveup.care/",
    "omop": "https://www.ohdsi.org/data-standardization/",
    "openEHR": "http://openehr.org/",
    "owl": "http://www.w3.org/2002/07/owl#",
    "phro": "https://ns.faqir.org/phr-o#",
    "prov": "http://www.w3.org/ns/prov#",
    "qo": "https://ns.faqir.org/q-o#",
    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
    "rdfs": "http://www.w3.org/2000/01/rdf-schema#",
    "rml": "http://w3id.org/rml/",
    "saref": "https://saref.etsi.org/core/",
    "schema": "http://schema.org/",
    "snomed": "http://snomed.info/sct/",
    "sosa": "http://www.w3.org/ns/sosa/",
    "sphn": "https://sphn.ch/",
    "s4ehaw": "https://saref.etsi.org/saref4ehaw",
    "tmp": "https://www2.telemonitoring-prescription.com/openapi#",
    "ucum": "https://unitsofmeasure.org/"
};
export const BAR_PROCEDURE_SLICE_SCHEMA = `
type Query {
    bariatricProcedures: [sphn_MedicalProcedure!]
}

type sphn_MedicalProcedure {
    id: ID!
    prov_type: ID! @filter(if: "it=in=('snomed:442338001', 'snomed:427074001')")
    prov_startedAtTime: DateTime!
    prov_endedAtTime: DateTime
    subject: ID!
        @predicate(iri: "sphn:hasIntervention", reverse: true)
}

type Subscription {
  onbariatricProcedureAdded: sphn_MedicalProcedure!
}`;

export const PROCEDURE_QUERY = `
PREFIX sphn: <https://sphn.ch/>
PREFIX prov: <http://www.w3.org/ns/prov#>
SELECT ?patient ?procedure ?timestamp WHERE {
  ?patient sphn:hasIntervention ?procedure .
  ?procedure a sphn:MedicalProcedure ;
    prov:startedAtTime ?timestamp .
}`;

export const QUESTIONNAIRE_SLICE_CONTEXT = {
  "brbdr": "https://www.sciensano.be/en/",
  "dcterms": "http://purl.org/dc/terms/",
  "ePPO": "https://bioportal.bioontology.org/ontologies/E-PPO",
  "faqir": "https://data.faqir.org/",
  "fhir": "http://hl7.org/fhir/",
  "foaf": "http://xmlns.com/foaf/0.1/",
  "kss": "https://kvasir.discover.ilabt.imec.be/vocab#",
  "moveup": "https://moveup.care/",
  "omop": "https://www.ohdsi.org/data-standardization/",
  "openEHR": "http://openehr.org/",
  "owl": "http://www.w3.org/2002/07/owl#",
  "phro": "https://ns.faqir.org/phr-o#",
  "prov": "http://www.w3.org/ns/prov#",
  "qo": "https://ns.faqir.org/q-o#",
  "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
  "rdfs": "http://www.w3.org/2000/01/rdf-schema#",
  "rml": "http://w3id.org/rml/",
  "saref": "https://saref.etsi.org/core/",
  "schema": "http://schema.org/",
  "snomed": "http://snomed.info/sct/",
  "sosa": "http://www.w3.org/ns/sosa/",
  "sphn": "https://sphn.ch/",
  "s4ehaw": "https://saref.etsi.org/saref4ehaw",
  "tmp": "https://www2.telemonitoring-prescription.com/openapi#",
  "ucum": "https://unitsofmeasure.org/"
};

export const QUESTIONNAIRE_PREOP_SLICE_SCHEMA = `
type Query {
  completedPreopBariatricResponses: [CompletedPreopBariatricResponse!]!
}

type CompletedPreopBariatricResponse @class(iri: "qo:QuestionnaireResponse") {
  id: ID!
  prov_atTime: DateTime!
  qo_questionnaireResponseToQuestionnaire: ID!
    @filter(if: "it=='https://moveup.care/Questionnaire/cX2u2njqWR8ErehW4'") #combined preop
  qo_questionnaireResponseBySubject: ID!
  dcterms_hasPart: [qo_Answer!]!
  fhir_status: [fhir_EventStatus!]
}

type qo_Answer {
  id: ID!
  qo_answerValue: [BoxedLiteral]
  qo_answerToQuestion: ID!
}

type fhir_EventStatus {
  id: ID!
  saref_hasValue: ID!
    @filter(
      if: "it=='http://hl7.org/fhir/questionnaire-answers-status#completed'"
    )
  saref_hasTimestamp: DateTime!
}

type Subscription {
  onCompletedPreopBariatricResponseAdded: CompletedPreopBariatricResponse!
}`;

export const QUESTIONNAIRE_POSTOP6W_SLICE_SCHEMA = `
type Query {
  completedPostop6wBariatricResponses: [CompletedPostop6wBariatricResponse!]!
}

type CompletedPostop6wBariatricResponse
  @class(iri: "qo:QuestionnaireResponse") {
  id: ID!
  prov_atTime: DateTime!
  qo_questionnaireResponseToQuestionnaire: ID!
    @filter(if: "it=='https://moveup.care/Questionnaire/5fsdff4wqtzLEPqaQ'") #combined Postop6w
  qo_questionnaireResponseBySubject: ID!
  dcterms_hasPart: [qo_Answer!]!
  fhir_status: [fhir_EventStatus!]
}

type qo_Answer {
  id: ID!
  qo_answerValue: [BoxedLiteral]
  qo_answerToQuestion: ID!
}

type fhir_EventStatus {
  id: ID!
  saref_hasValue: ID!
    @filter(
      if: "it=='http://hl7.org/fhir/questionnaire-answers-status#completed'"
    )
  saref_hasTimestamp: DateTime!
}

type Subscription {
  onCompletedPostop6wBariatricResponseAdded: CompletedPostop6wBariatricResponse!
}`;

export const QUESTIONNAIRE_POSTOP3M_SLICE_SCHEMA = `
type Query {
  completedPostop3mBariatricResponses: [CompletedPostop3mBariatricResponse!]!
}

type CompletedPostop3mBariatricResponse
  @class(iri: "qo:QuestionnaireResponse") {
  id: ID!
  prov_atTime: DateTime!
  qo_questionnaireResponseToQuestionnaire: ID!
    @filter(if: "it=='https://moveup.care/Questionnaire/TpYG3bjxPT4QCwg9A'") #combined Postop3m
  qo_questionnaireResponseBySubject: ID!
  dcterms_hasPart: [qo_Answer!]!
  fhir_status: [fhir_EventStatus!]
}

type qo_Answer {
  id: ID!
  qo_answerValue: [BoxedLiteral]
  qo_answerToQuestion: ID!
}

type fhir_EventStatus {
  id: ID!
  saref_hasValue: ID!
    @filter(
      if: "it=='http://hl7.org/fhir/questionnaire-answers-status#completed'"
    )
  saref_hasTimestamp: DateTime!
}

type Subscription {
  onCompletedPostop3mBariatricResponseAdded: CompletedPostop3mBariatricResponse!
}`;

export const QUESTIONNAIRE_POSTOP6M_SLICE_SCHEMA = `
type Query {
  completedPostop6mBariatricResponses: [CompletedPostop6mBariatricResponse!]!
}

type CompletedPostop6mBariatricResponse
  @class(iri: "qo:QuestionnaireResponse") {
  id: ID!
  prov_atTime: DateTime!
  qo_questionnaireResponseToQuestionnaire: ID!
    @filter(if: "it=='https://moveup.care/Questionnaire/5cdZ4Qd7uWgSQ29B8'") #combined Postop6m
  qo_questionnaireResponseBySubject: ID!
  dcterms_hasPart: [qo_Answer!]!
  fhir_status: [fhir_EventStatus!]
}

type qo_Answer {
  id: ID!
  qo_answerValue: [BoxedLiteral]
  qo_answerToQuestion: ID!
}

type fhir_EventStatus {
  id: ID!
  saref_hasValue: ID!
    @filter(
      if: "it=='http://hl7.org/fhir/questionnaire-answers-status#completed'"
    )
  saref_hasTimestamp: DateTime!
}

type Subscription {
  onCompletedPostop6mBariatricResponseAdded: CompletedPostop6mBariatricResponse!
}`;

export const QUESTIONNAIRE_POSTOP1Y_SLICE_SCHEMA = `
type Query {
  completedPostop1yBariatricResponses: [CompletedPostop1yBariatricResponse!]!
}

type CompletedPostop1yBariatricResponse
  @class(iri: "qo:QuestionnaireResponse") {
  id: ID!
  prov_atTime: DateTime!
  qo_questionnaireResponseToQuestionnaire: ID!
    @filter(if: "it=='https://moveup.care/Questionnaire/MDZj8qTHYXaEf3zDX'") #combined Postop1y
  qo_questionnaireResponseBySubject: ID!
  dcterms_hasPart: [qo_Answer!]!
  fhir_status: [fhir_EventStatus!]
}

type qo_Answer {
  id: ID!
  qo_answerValue: [BoxedLiteral]
  qo_answerToQuestion: ID!
}

type fhir_EventStatus {
  id: ID!
  saref_hasValue: ID!
    @filter(
      if: "it=='http://hl7.org/fhir/questionnaire-answers-status#completed'"
    )
  saref_hasTimestamp: DateTime!
}

type Subscription {
  onCompletedPostop1yBariatricResponseAdded: CompletedPostop1yBariatricResponse!
}`;

export const QUESTIONNAIRE_QUERY = `
PREFIX dcterms: <http://purl.org/dc/terms/>
PREFIX qo: <https://ns.faqir.org/q-o#>
SELECT ?res ?patient ?questionnaire ?value ?question WHERE {
  ?res a qo:QuestionnaireResponse ;
    qo:questionnaireResponseBySubject ?patient ;
    qo:questionnaireResponseToQuestionnaire ?questionnaire ;
    dcterms:hasPart ?answer .
  ?answer a qo:Answer ;
    qo:answerValue ?value ;
    qo:answerToQuestion ?question .
}
`;
