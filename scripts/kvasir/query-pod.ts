import { QueryEngine } from "@incremunica/query-sparql-incremental";
import { isAddition } from "@incremunica/user-tools";
import { KeycloakOIDCAuth } from "../util.js";

const POD_URL = "http://localhost:8080/alice";
const IDP = "http://localhost:8280";
const REALM = "quarkus";
const CLIENT_ID = "demo-client";
const CLIENT_SECRET = "oI6T6JNZR8ezbnWJafRIQtQrNIXCBqOh";

const USERNAME = "alice";
const PASSWORD = "alice";

const engine = new QueryEngine();
const auth = new KeycloakOIDCAuth();

await auth.init(IDP, REALM);
await auth.login(USERNAME, PASSWORD, CLIENT_ID, CLIENT_SECRET);

const SLICE = `${POD_URL}/slices/AggregatorDemoSlice/query`;

const QUERY = `
PREFIX ex: <http://example.org/>
SELECT ?pat ?value ?unit ?timestamp 
WHERE {
  ?pat ex:hasObservation ?obs .
  ?obs ex:value ?value ;
       ex:unit ?unit ;
       ex:timestamp ?timestamp .
}
`;

const CONTEXT = {
  kss: "https://kvasir.discover.ilabt.imec.be/vocab#",
  schema: "http://schema.org/",
  ex: "http://example.org/",
};

const SCHEMA = `
type Query {
  observations: [ex_Observation]!
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
`;

const bindingsStream = await engine.queryBindings(QUERY, {
  sources: [
    {
      type: "graphql",
      value: SLICE,
      context: {
        schema: SCHEMA,
        context: CONTEXT,
      },
    },
  ],
  fetch: auth.createUMAFetch(),
});

console.log("BINDING STREAM STARTED");

bindingsStream.on("data", (bindings) => {
  console.log("Is addition:", isAddition(bindings));
  console.log(bindings.toString());
});

bindingsStream.on("end", () => {});

bindingsStream.on("error", (error) => {
  console.error(error);
});
