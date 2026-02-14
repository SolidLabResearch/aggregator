import { fetch } from "cross-fetch";
import { randomUUID } from "crypto";
import {SolidOIDCAuth} from "../util.js";

const AGGREGATOR_URL = "http://aggregator.local:5000";

const QUERY_SOURCES = ["http://rs.local:3000/bob/favorites", "http://rs.local:3000/alice/favorites"];
const QUERY_STRING = "SELECT ?favorite WHERE { ?s schema:name ?favorite }";

function buildPipelineDescription(sources: string[], query: string, transformationsCatalog: string): string {
  return `
@prefix config: <${transformationsCatalog}> .
@prefix fno: <https://w3id.org/function/ontology#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .

_:execution a fno:Execution ;
    fno:executes config:SPARQLEvaluation ;
    config:sources ( ${sources.map(source => `"${source}"^^xsd:string`).join(" ")} ) ;
    config:queryString "${query}" .
`.trim();
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function formatRequestUrl(input: string | URL | Request): string {
  if (typeof input === "string") {
    return input;
  }
  if (input instanceof URL) {
    return input.toString();
  }
  return input.url;
}

async function timedFetch(
  label: string,
  input: string | URL | Request,
  init: RequestInit | undefined,
  customFetch: typeof fetch = fetch,
) {
  const method = init?.method || (input instanceof Request ? input.method : "GET");
  const url = formatRequestUrl(input);
  const started = Date.now();
  try {
    const resp = await customFetch(input, init);
    const elapsed = Date.now() - started;
    console.log(`[timing] ${label}: ${method} ${url} -> ${resp.status} in ${elapsed}ms`);
    return resp;
  } catch (err) {
    const elapsed = Date.now() - started;
    console.log(`[timing] ${label}: ${method} ${url} failed after ${elapsed}ms`);
    throw err;
  }
}

async function fetchWithRetry(
  input: string | URL | Request,
  timeoutMs: number,
  init?: RequestInit | undefined,
  customFetch: typeof fetch = fetch,
  label = "request",
) {
  const started = Date.now();
  let attempt = 0;
  while (Date.now() - started < timeoutMs) {
    attempt += 1;
    const resp = await timedFetch(`${label} (attempt ${attempt})`, input, init, customFetch);
    if (resp.ok) {
      return resp;
    }
    if (resp.status !== 503) {
      return resp;
    }

    console.log(`    Endpoint not ready yet, retrying...`);
    const retryAfter = resp.headers.get("retry-after");
    const retrySeconds = retryAfter ? Number.parseInt(retryAfter, 10) : NaN;
    const delayMs = Number.isFinite(retrySeconds) ? retrySeconds * 1000 : 2000;
    await sleep(delayMs);
  }

  return timedFetch(`${label} (final)`, input, init, customFetch);
}

function buildPolicyBody(
  target: string,
  assignee: string,
  assigner: string,
  actions: string[],
): string {
  const policyId = `policy-${randomUUID()}`;
  const permissionId = `permission-${randomUUID()}`;
  const actionList = actions.length > 0 ? actions.join(", ") : "odrl:read";

  return [
    "@prefix ex: <http://example.org/>.",
    "@prefix odrl: <http://www.w3.org/ns/odrl/2/> .",
    "@prefix dct: <http://purl.org/dc/terms/>.",
    "",
    `ex:${policyId} a odrl:Agreement ;`,
    `               odrl:uid ex:${policyId} ;`,
    `               odrl:permission ex:${permissionId} .`,
    "",
    `ex:${permissionId} a odrl:Permission ;`,
    `              odrl:action ${actionList} ;`,
    `              odrl:target <${target}> ;`,
    `              odrl:assignee <${assignee}> ;`,
    `              odrl:assigner <${assigner}> .`,
  ].join("\n");
}

async function createPolicy(
  label: string,
  policyEndpoint: string,
  ownerWebId: string,
  target: string,
  assignee: string,
  actions: string[],
) {
  const policyBody = buildPolicyBody(target, assignee, ownerWebId, actions);
  const authHeader = `WebID ${encodeURIComponent(ownerWebId)}`;
  const resp = await timedFetch(
    label,
    policyEndpoint,
    {
      method: "POST",
      headers: {
        "content-type": "text/turtle",
        authorization: authHeader,
      },
      body: policyBody,
    },
    fetch,
  );

  if (!resp.ok) {
    throw new Error(`Failed to create policy for ${target}: ${resp.status} ${await resp.text()}`);
  }
}

async function ensureContainer(
  label: string,
  containerUrl: string,
  authFetch: typeof fetch,
) {
  const resp = await timedFetch(
    label,
    containerUrl,
    {
      method: "PUT",
      headers: {
        "content-type": "text/turtle",
        link: '<http://www.w3.org/ns/ldp#BasicContainer>; rel="type"',
      },
      body: "",
    },
    authFetch,
  );

  if (resp.ok || resp.status === 409 || resp.status === 412) {
    return;
  }

  throw new Error(`Failed to create container ${containerUrl}: ${resp.status} ${await resp.text()}`);
}

async function putResource(
  label: string,
  resourceUrl: string,
  body: string,
  authFetch: typeof fetch,
) {
  const resp = await timedFetch(
    label,
    resourceUrl,
    {
      method: "PUT",
      headers: {
        "content-type": "text/turtle",
      },
      body,
    },
    authFetch,
  );

  if (!resp.ok) {
    throw new Error(`Failed to create resource ${resourceUrl}: ${resp.status} ${await resp.text()}`);
  }
}

async function main() {
  console.log(`=== Initializing Solid OIDC authentication`);
  const auth = new SolidOIDCAuth(
    'http://rs.local:3000/alice/profile/card#me',
    'http://rs.local:3000'
  );
  await auth.init('alice@example.org', 'abc123');
  console.log(`=== Solid OIDC authentication initialized successfully\n`);

  console.log(`=== Initializing Solid OIDC authentication 2`);
  const authBob = new SolidOIDCAuth(
    'http://rs.local:3000/bob/profile/card#me',
    'http://rs.local:3000'
  );
  await authBob.init('bob@example.org', 'abc123');
  console.log(`=== Solid OIDC authentication initialized successfully\n`);

  const authFetch = auth.createAuthFetch();
  const authFetchBob = authBob.createAuthFetch();
  console.log("=== Creating CSS policies");
  const umaPoliciesEndpoint = "http://uma.local:4000/uma/policies";
  await createPolicy(
    "alice create policy",
    umaPoliciesEndpoint,
    "http://rs.local:3000/alice/profile/card#me",
    "http://rs.local:3000/alice/",
    "http://rs.local:3000/alice/profile/card#me",
    ["odrl:modify", "odrl:create", "odrl:delete", "odrl:read"],
  );
  await createPolicy(
    "bob create policy",
    umaPoliciesEndpoint,
    "http://rs.local:3000/bob/profile/card#me",
    "http://rs.local:3000/bob/",
    "http://rs.local:3000/bob/profile/card#me",
    ["odrl:modify", "odrl:create", "odrl:delete", "odrl:read"],
  );

  console.log("=== Creating favorites resources");
  await putResource(
    "alice favorites resource",
    "http://rs.local:3000/alice/favorites",
    '@prefix schema: <http://schema.org/> .\n<#fav> schema:name "Semantics" .\n',
    authFetch,
  );
  await putResource(
    "bob favorites resource",
    "http://rs.local:3000/bob/favorites",
    '@prefix schema: <http://schema.org/> .\n<#fav> schema:name "ISWC" .\n',
    authFetchBob,
  );
  await createPolicy(
    "alice favorites access for demo",
    umaPoliciesEndpoint,
    "http://rs.local:3000/alice/profile/card#me",
    "http://rs.local:3000/alice/favorites",
    "http://rs.local:3000/alice/profile/card#me",
    ["odrl:modify", "odrl:create", "odrl:delete", "odrl:read"],
  );
  await createPolicy(
    "bob favorites access for demo",
    umaPoliciesEndpoint,
    "http://rs.local:3000/bob/profile/card#me",
    "http://rs.local:3000/bob/favorites",
    "http://rs.local:3000/bob/profile/card#me",
    ["odrl:modify", "odrl:create", "odrl:delete", "odrl:read"],
  );
  await createPolicy(
    "alice favorites access for demo",
    umaPoliciesEndpoint,
    "http://rs.local:3000/alice/profile/card#me",
    "http://rs.local:3000/alice/favorites",
    "http://rs.local:3000/demo/profile/card#me",
    ["odrl:read"],
  );
  await createPolicy(
    "bob favorites access for demo",
    umaPoliciesEndpoint,
    "http://rs.local:3000/bob/profile/card#me",
    "http://rs.local:3000/bob/favorites",
    "http://rs.local:3000/demo/profile/card#me",
    ["odrl:read"],
  );

  const aggregatorServerResponse = await timedFetch(
    "aggregator server description",
    AGGREGATOR_URL,
    { method: "GET" },
    authFetch,
  );
  const aggregatorServerDescription = await aggregatorServerResponse.json();

  console.log(`=== Registering provision flow at ${aggregatorServerDescription.registration_endpoint}`);
  const registrationResponse = await timedFetch(
    "register provision",
    aggregatorServerDescription.registration_endpoint,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({ registration_type: "provision" }),
    },
    authFetch,
  );

  if (!registrationResponse.ok) {
    console.error(`Error during registration: ${registrationResponse.status} - ${await registrationResponse.text()}`);
    return;
  }

  const registration = await registrationResponse.json();
  const aggregatorID = registration.aggregator_id;
  const aggregatorURL = registration.aggregator;
  console.log(`=== Aggregator registered: ${aggregatorID}`);

  if (!aggregatorURL) {
    throw new Error("No aggregator URL returned upon registration");
  }

  console.log(`=== Fetching aggregator description at ${aggregatorURL}`);
  const aggregatorDescriptionResponse = await fetchWithRetry(
    aggregatorURL,
    60000,
    { method: "GET" },
    authFetch,
    "aggregator description",
  );
  const aggregatorDescription = await aggregatorDescriptionResponse.json();
  const serviceCollection = aggregatorDescription.service_collection;

  const requestBody = buildPipelineDescription(QUERY_SOURCES, QUERY_STRING, aggregatorServerDescription.transformation_catalog);

  console.log(`=== Creating service via ${serviceCollection}`);
  const serviceResp = await timedFetch(
    "create service",
    serviceCollection,
    {
      method: "POST",
      headers: {
        "content-type": "text/turtle",
      },
      body: requestBody,
    },
    authFetch,
  );

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
      const statusResp = await timedFetch(
        "service status",
        serviceResourceURL,
        { method: "GET" },
        authFetch,
      );
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
  const resultsResp = await fetchWithRetry(
    serviceEndpoint,
    500,
    { method: "GET" },
    authFetch,
    "query results",
  );
  if (!resultsResp.ok) {
    throw new Error(
      `Failed to fetch service results: ${resultsResp.status} ${await resultsResp.text()}`,
    );
  }
  const results = await resultsResp.text();
  console.log("=== Query results");
  console.log(results);

  console.log(`=== Fetching query results from ${serviceEndpoint}`);
  const resultsRespBob = await fetchWithRetry(
    serviceEndpoint,
    500,
    { method: "GET" },
    authFetchBob,
    "query results",
  );
  if (!resultsRespBob.ok) {
    throw new Error(
      `Failed to fetch service results: ${resultsRespBob.status} ${await resultsRespBob.text()}`,
    );
  }
  const resultsBob = await resultsRespBob.text();
  console.log("=== Query results");
  console.log(resultsBob);
}

main().catch((err) => {
  console.error("Error in register-provision script:");
  console.error(err);
  process.exit(1);
});
