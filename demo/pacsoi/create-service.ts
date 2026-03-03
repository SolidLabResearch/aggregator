import { KeycloakOIDCAuth } from "../util.js";
import { DataFactory } from "rdf-data-factory";
import { Writer } from "n3";

const df = new DataFactory();

// Aggregator configuration
const AGGREGATOR_SERVER = "https://aggregator.local:5443";
const AGGREGATOR = "https://aggregator.local:5443/419d851a-a6ab-4273-815d-0e59b6b44db4";
const TF = "/transformations";
const SVC = "/services";

// Transformation configuration
const SVC_NAME = "pacsoi-svc";
const TF_ID = "Pacsoi";
const PARAMS = {};

// Authz configuration
const USERNAME = "alice";
const PASSWORD = "alice";
const CLIENT_ID = "demo-client";
const CLIENT_SECRET = "SsIyMNGjbKrbcJPHr8gWwc36DdqMGvvd";
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
