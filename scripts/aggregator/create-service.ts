import { KeycloakOIDCAuth } from "../util.js";
import { DataFactory } from "rdf-data-factory";
import { Writer } from "n3";

const df = new DataFactory();

// Aggregator configuration
const AGGREGATOR_SERVER = "https://aggregator.local:5443";
const AGGREGATOR = "https://aggregator.local:5443/54337f85-02a7-4e04-8f29-a7d46c63ce03";
const TF = "/transformations";
const SVC = "/services";

// Transformation configuration
const SVC_NAME = "kvasir-query-svc";
const TF_ID = "KvasirQuery";
const PARAMS = {
  query: `
  PREFIX ex: <http://example.org/>
  SELECT ?pat ?value ?unit ?timestamp 
  WHERE {
    ?pat ex:hasObservation ?obs .
    ?obs ex:value ?value ;
        ex:unit ?unit ;
        ex:timestamp ?timestamp .
  }`,
  sources: "http://localhost:8080/alice/slices/AggregatorDemoSlice/query",
  schema: `
  type Query {
    observations: [ex_Observation]!
    observation(id: ID!): ex_Observation
  }

  type ex_Patient {
    id: ID!
  }

  type ex_Observation {
    id: ID!
    ex_value: Int!
    ex_unit: String!
    ex_timestamp: DateTime!
    forPatient: ex_Patient! @predicate(iri: "ex:hasObservation", reverse: true)
  }

  type Subscription {
    observationAdded: ex_Observation!
  }

  type Mutation {
    add(obs: PatientObservationInput!): ID!
  }

  input ObservationInput @class(iri: "ex:Observation") {
    id: ID!
    ex_value: Int!
    ex_unit: String!
    ex_timestamp: DateTime!
  }

  input PatientObservationInput @class(iri: "ex:Patient") {
    id: ID!
    ex_hasObservation: ObservationInput!
  }
  `,
  context: JSON.stringify({
    kss: "https://kvasir.discover.ilabt.imec.be/vocab#",
    schema: "http://schema.org/",
    ex: "http://example.org/",
  })
};

// Authz configuration
const USERNAME = "alice";
const PASSWORD = "alice";
const CLIENT_ID = "demo-client";
const CLIENT_SECRET = "oI6T6JNZR8ezbnWJafRIQtQrNIXCBqOh";
const IDP = "http://localhost:8280";
const REALM = "quarkus";

const auth = new KeycloakOIDCAuth()
await auth.init(IDP, REALM)
await auth.login(USERNAME, PASSWORD, CLIENT_ID, CLIENT_SECRET);
const umaFetch = auth.createUMAFetch();

async function createService() {
    console.log(`=== Parsing service request ===`);

    const desc = await parseServiceRequest(SVC_NAME, TF_ID, PARAMS);
    console.log(desc)

    console.log(`=== Creating service at ${AGGREGATOR}${SVC} ===`);

    const serviceRequest = {
        method: "POST",
        headers: { "content-type": "text/turtle" },
        body: desc
    };

    const response = await umaFetch(AGGREGATOR+SVC, serviceRequest);
    console.log(`=== Response status: ${response.status} ===`);

    if (response.status !== 202 && response.status !== 201) {
        throw new Error(`Error: ${response.status}, response: ${await response.text()}`);
    }

    console.log(`=== Service accepted ===`);
    const service = await response.text();
    console.log(service);
}

async function main() {
    await createService();
}

async function parseServiceRequest(
  name: string,
  id: string,
  params: Record<string, string>
): Promise<string> {

  const writer = new Writer({
    prefixes: {
      trans: `${AGGREGATOR_SERVER}${TF}#`,
      fno: "https://w3id.org/function/ontology#",
      rdf: "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
      xsd: "http://www.w3.org/2001/XMLSchema#",
    }
  });

  const execution = df.namedNode(`${AGGREGATOR}/${name}`);

  // rdf:type fno:Execution
  writer.addQuad(
    execution,
    df.namedNode("http://www.w3.org/1999/02/22-rdf-syntax-ns#type"),
    df.namedNode("https://w3id.org/function/ontology#Execution")
  );

  // fno:executes trans:$id
  writer.addQuad(
    execution,
    df.namedNode("https://w3id.org/function/ontology#executes"),
    df.namedNode(`${AGGREGATOR_SERVER}${TF}#${id}`)
  );

  // parameters
  for (const [key, value] of Object.entries(params)) {
    writer.addQuad(
      execution,
      df.namedNode(`${AGGREGATOR_SERVER}${TF}#${key}`),
      df.literal(value)
    );
  }

  // Return Turtle string
  return new Promise((resolve, reject) => {
    writer.end((error, result) => {
      if (error) reject(error);
      else resolve(result);
    });
  });
}

main().catch(console.error);
