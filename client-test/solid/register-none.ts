import { fetch } from "cross-fetch";

const AGGREGATOR_URL = "http://aggregator.local";

const QUERY_SOURCE = "http://rs.local:3000/bob/profile/card";
const QUERY_STRING = "SELECT * WHERE { ?s ?p ?o }";

function buildPipelineDescription(source: string, query: string, transformationsCatalog: string): string {
  return `
@prefix config: <${transformationsCatalog}> .
@prefix fno: <https://w3id.org/function/ontology#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .

_:execution a fno:Execution ;
    fno:executes config:SPARQLEvaluation ;
    config:sources ( "${source}"^^xsd:string ) ;
    config:queryString "${query}" .
`.trim();
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchWithRetry(
  input: string | URL | Request,
  timeoutMs: number,
  init?: RequestInit | undefined
) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const resp = await fetch(input, init);
    if (resp.ok) {
      return resp;
    }
    if (resp.status !== 503) {
      return resp;
    }

    const retryAfter = resp.headers.get("retry-after");
    const retrySeconds = retryAfter ? Number.parseInt(retryAfter, 10) : NaN;
    const delayMs = Number.isFinite(retrySeconds) ? retrySeconds * 1000 : 2000;
    await sleep(delayMs);
  }

  return fetch(input, init);
}

async function main() {
  const aggregatorServerDescription = await (await fetch(AGGREGATOR_URL, { method: "GET" })).json();

  console.log(`=== Registering none flow at ${aggregatorServerDescription.registration_endpoint}`);
  const registrationResponse = await fetch(aggregatorServerDescription.registration_endpoint, {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({ registration_type: "none" }),
  });

  if (registrationResponse.status !== 201) {
    const errorBody = await registrationResponse.text();
    throw new Error(
      `Registration failed: ${registrationResponse.status} ${errorBody}`,
    );
  }

  const registration = await registrationResponse.json();
  const aggregatorID = registration.aggregator_id;
  const aggregatorURL = registration.aggregator;
  console.log(`=== Aggregator registered: ${aggregatorID}`);

  if (!aggregatorURL) {
    throw new Error("No aggregator URL returned upon registration");
  }

  console.log(`=== Fetching aggregator description at ${aggregatorURL}`);
  const aggregatorDescription = await (await fetchWithRetry(aggregatorURL, 60000, {method: "GET"})).json();
  const serviceCollection = aggregatorDescription.service_collection;

  const requestBody = buildPipelineDescription(QUERY_SOURCE, QUERY_STRING, aggregatorServerDescription.transformation_catalog);

  console.log(`=== Creating service via ${serviceCollection}`);
  const serviceResp = await fetch(serviceCollection, {
    method: "POST",
    headers: {
      "content-type": "text/turtle",
    },
    body: requestBody,
  });

  if (serviceResp.status !== 201 && serviceResp.status !== 202) {
    const errorBody = await serviceResp.text();
    throw new Error(
      `Service creation failed: ${serviceResp.status} ${errorBody}`,
    );
  }

  const contentType = serviceResp.headers.get("content-type") || "";
  let serviceEndpoint = "";
  let serviceResourceURL = "";
  if (contentType.includes("application/json")) {
    const serviceDescription = await serviceResp.json();
    serviceResourceURL = serviceDescription.id;
    
    // Poll until service is running
    console.log(`=== Waiting for service to be ready...`);
    const pollStarted = Date.now();
    const pollTimeout = 10000; // 10 seconds
    
    while (Date.now() - pollStarted < pollTimeout) {
      const statusResp = await fetch(serviceResourceURL, { method: "GET" });
      if (!statusResp.ok) {
        throw new Error(`Failed to fetch service status: ${statusResp.status}`);
      }
      
      const serviceResource = await statusResp.json();
      console.log(`    Service status: ${serviceResource.status}`);
      
      if (serviceResource.status === "running") {
        if (Array.isArray(serviceResource.endpoints) && serviceResource.endpoints.length > 0) {
          serviceEndpoint = serviceResource.endpoints[0];
        } else {
          serviceEndpoint = serviceResource.location;
        }
        break;
      }
      
      if (serviceResource.status === "errored") {
        throw new Error("Service entered errored state");
      }
      
      await sleep(1000); // Wait 1 seconds before polling again
    }
    
    if (!serviceEndpoint) {
      throw new Error("Service did not become ready within timeout");
    }
  }

  if (!serviceEndpoint) {
    throw new Error("Service endpoint not returned by service collection");
  }

  console.log(`=== Fetching query results from ${serviceEndpoint}`);
  const resultsResp = await fetch(serviceEndpoint, {method: "GET"});
  if (!resultsResp.ok) {
    throw new Error(
      `Failed to fetch service results: ${resultsResp.status} ${await resultsResp.text()}`,
    );
  }
  const results = await resultsResp.text();
  console.log("=== Query results");
  console.log(results);
}

main().catch((err) => {
  console.error("❌ Flow failed");
  console.error(err?.message || err);
  process.exitCode = 1;
});
