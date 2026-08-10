/**
 * GraphQL-LD schemas, JSON-LD contexts, and SPARQL queries used by query.ts.
 *
 * The schema describes each remote slice to the query engine; the paired
 * context expands its compact field names into RDF predicates. The SELECT
 * variable names are an internal API: query.ts reads these exact binding names.
 */
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
// Keep ?patient in the projection: querySources uses it to clean both
// distributions when the doctor-to-patient relation is deleted.
export const HCP_QUERY = `
PREFIX faqir: <https://faqir.org/>
SELECT ?patient ?pod WHERE {
  ?patient faqir:podId ?pod ;
    faqir:pt_hcp ?doctor .
}`;

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
  "prov": "https://www.w3.org/TR/prov-o/",
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
    ?patient a foaf:Person .

    OPTIONAL {
      ?patient sphn:hasIdentifier ?identifier .
      ?identifier saref:hasValue ?idValue ;
        fhir:issuer ?issuer .
    }
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
  "prov": "https://www.w3.org/TR/prov-o/",
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
  ...
}

// TODO make sure this property is a weight property
// How do we do this?
type WeightProperty @class(iri: "saref:Property"){
    id: ID!
}

type WeightValue @class(iri: "saref:PropertyValue") {
    id: ID!
    saref_isValueOfProperty: WeightProperty!
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
    "prov": "https://www.w3.org/TR/prov-o/",
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

export const KNEE_PROCEDURE_SLICE_CONTEXT = {
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
    "prov": "https://www.w3.org/TR/prov-o/",
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
export const KNEE_PROCEDURE_SLICE_SCHEMA = `
type Query {
    kneeProcedures: [sphn_MedicalProcedure!]
}

type sphn_MedicalProcedure  {
    id: ID!
    prov_type: ID! @filter(if: "it=in=('snomed:444463001', 'snomed:443682009', 'snomed:443681002', 'snomed:726419008', 'snomed:726418000', 'snomed:735261001', 'snomed:735262008')")
    prov_startedAtTime: DateTime!
    prov_endedAtTime: DateTime
    subject: ID!
        @predicate(iri: "sphn:hasIntervention", reverse: true)
}

type Subscription {
  onKneeProcedureAdded: sphn_MedicalProcedure!
}`;
export const PROCEDURE_QUERY = `
PREFIX sphn: <https://sphn.ch/>
PREFIX prov: <https://www.w3.org/TR/prov-o/>
SELECT ?patient ?timestamp WHERE {
  ?patient sphn:hasIntervention ?proc .
  ?proc a sphn:MedicalProcedure ;
    prov:startedAtTime ?timestamp .
}`;

export const OXFORD_SLICE_CONTEXT = {
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
  "prov": "https://www.w3.org/TR/prov-o/",
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
export const OXFORD_SLICE_SCHEMA = `
type Query {
  completedOxfordResponses: [CompletedOxfordResponse!]!
}

type CompletedOxfordResponse @class(iri: "qo:QuestionnaireResponse") {
  id: ID!
  prov_atTime: DateTime!
  qo_questionnaireResponseToQuestionnaire: qo_Questionnaire!
  qo_questionnaireResponseBySubject: ID!
  dcterms_hasPart: [qo_Answer!]!
  fhir_status: String! @filter(if: "it=='completed'")
}

type qo_Answer {
  id: ID!
  qo_answerValue: [BoxedLiteral]
  qo_answerToQuestion: ID!
}

type qo_Questionnaire {
  id: ID!
  rdfs_label: String! @filter(if: "it=='oxford'")
}

type Subscription {
  onCompletedOxfordResponseAdded: CompletedOxfordResponse!
}`;

export const OXFORD_QUERY = `
PREFIX moveUp: <http://moveup.care/>
PREFIX prov: <https://www.w3.org/TR/prov-o/>
PREFIX dcterms: <http://purl.org/dc/terms/>
PREFIX qo: <https://ns.faqir.org/q-o#>
SELECT ?res ?timestamp ?patient ?question ?value WHERE {
    ?res a qo:QuestionnaireResponse ;
        prov:atTime ?timestamp ;
        qo:questionnaireResponseBySubject ?patient ;
        dcterms:hasPart ?answer .
    ?answer qo:answerValue ?value ;
        qo:answerToQuestion ?question
}`;
