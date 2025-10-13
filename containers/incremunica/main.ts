import { QueryEngine } from '@comunica/query-sparql';
import { QueryEngine as QueryEngineInc } from '@incremunica/query-sparql-incremental';
import { isAddition, QuerySourceIterator } from '@incremunica/user-tools';
import { Store, Parser, DataFactory } from 'n3';
import http from "http";
import { URL } from "url";

// SSE Connection Manager
class SSEConnectionManager {
  private connections: Set<http.ServerResponse> = new Set();

  addConnection(res: http.ServerResponse): void {
    this.connections.add(res);
    res.on('close', () => {
      this.connections.delete(res);
    });
  }

  broadcast(event: string, data: any): void {
    const message = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const connection of this.connections) {
      try {
        connection.write(message);
      } catch (error) {
        // Remove connection if write fails
        this.connections.delete(connection);
      }
    }
  }

  sendToConnection(res: http.ServerResponse, event: string, data: any): void {
    const message = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
    try {
      res.write(message);
    } catch (error) {
      this.connections.delete(res);
    }
  }
}

// Resource registration configuration
const REGISTRATION_URL = "http://192.168.49.1:4449/register";
const POD_NAME = process.env.HOSTNAME || "incremunica-pod";
const POD_IP = process.env.POD_IP || "127.0.0.1";
const SERVICE_PORT = 8080;

const proxyUrl = process.env.http_proxy || process.env.HTTP_PROXY;
if (proxyUrl === undefined) {
  throw new Error('Environment variable PROXY_URL is not set. Please provide the URL of the proxy server.');
}

// Create custom fetch function that uses the proxy's /fetch endpoint
async function customFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const originalUrl = input.toString();

  // Prepare the request payload for the proxy
  const fetchRequest = {
    url: originalUrl,
    method: init?.method || 'GET',
    headers: init?.headers || {},
    body: init?.body ? init.body.toString() : ''
  };

  const response = await fetch(`${proxyUrl}/fetch`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(fetchRequest)
  });

  // Override the url property to return the original URL
  Object.defineProperty(response, 'url', {
    value: originalUrl,
    writable: false,
    enumerable: true,
    configurable: false
  });

  return response;
}

const TRANSFORMATIONS_NS = "http://localhost:5000/config/transformations#";
const RDF_NS = "http://www.w3.org/1999/02/22-rdf-syntax-ns#";

const RDF_TYPE = DataFactory.namedNode(`${RDF_NS}type`);
const RDF_FIRST = DataFactory.namedNode(`${RDF_NS}first`);
const RDF_REST = DataFactory.namedNode(`${RDF_NS}rest`);
const RDF_NIL = DataFactory.namedNode(`${RDF_NS}nil`);

const SPARQL_RESULT_SOURCE_CLASS = DataFactory.namedNode(`${TRANSFORMATIONS_NS}SPARQLQueryResultSource`);
const SPARQL_RESULT_PREDICATE = DataFactory.namedNode(`${TRANSFORMATIONS_NS}sparqlQueryResult`);
const EXTRACT_VARIABLES_PREDICATE = DataFactory.namedNode(`${TRANSFORMATIONS_NS}extractVariables`);

interface DynamicSourceConfig {
  endpoint: string;
  variables: string[];
}

// Function to register an endpoint with the aggregator
async function registerEndpointWithAggregator(endpoint: string, description: string, scopes: string[] = ["read"]): Promise<void> {
  const registrationData = {
    pod_name: POD_NAME,
    pod_ip: POD_IP,
    port: SERVICE_PORT,
    endpoint: endpoint,
    scopes: scopes,
    description: description
  };

  try {
    console.log(`📝 Registering endpoint ${endpoint} with aggregator at ${REGISTRATION_URL}`);
    console.log(`   Pod: ${POD_NAME}, IP: ${POD_IP}, Port: ${SERVICE_PORT}`);
    console.log(`   Description: ${description}`);

    const response = await fetch(REGISTRATION_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(registrationData)
    });

    if (response.ok) {
      const result = await response.json();
      console.log(`✅ Successfully registered endpoint ${endpoint}:`);
      console.log(`   External URL: ${result.external_url}`);
      console.log(`   Actor ID: ${result.actor_id}`);
      return result.actor_id;
    } else {
      const errorText = await response.text();
      console.error(`❌ Failed to register endpoint ${endpoint}: ${response.status} - ${errorText}`);
    }
  } catch (error) {
    console.error(`❌ Error registering endpoint ${endpoint}:`, error);
  }
}

// Function to register all endpoints with the aggregator
async function registerWithAggregator(): Promise<void> {
  console.log('🌐 Registering all endpoints with aggregator...');

  // Register the main SPARQL results endpoint
  await registerEndpointWithAggregator(
    "/",
    "SPARQL SELECT incremental query service - JSON results",
    ["read"]
  );

  // Register the server-sent events endpoint
  await registerEndpointWithAggregator(
    "/events",
    "SPARQL SELECT incremental query service - Real-time SSE stream",
    ["read"]
  );

  console.log('✅ All endpoints registered with aggregator');
}

async function main() {
  const pipelineDescription = process.env.PIPELINE_DESCRIPTION;
  if (pipelineDescription === undefined) {
    throw new Error('Environment variable PIPELINE_DESCRIPTION is not set. Please provide a valid pipeline description.');
  }
  const pipelineParsingEngine = new QueryEngine();
  const pipelineDescriptionStore = new Store();
  const parser = new Parser();

  await new Promise<void>(
    (resolve, reject) => {
      parser.parse(pipelineDescription, (error, quad, _prefixes) => {
        if (error) {
          reject('Error parsing pipeline description: ' + error);
          return;
        }
        if (quad) {
          pipelineDescriptionStore.addQuad(quad);
        } else {
          // Parsing finished
          resolve();
        }
      });
    }
  );

  const queryInfoStream = await pipelineParsingEngine.queryBindings(`
PREFIX fno: <https://w3id.org/function/ontology#>
PREFIX config: <http://localhost:5000/config#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>

SELECT ?queryString ?source WHERE {
    ?execution a fno:Execution .
    ?execution fno:executes config:SPARQLEvaluation .
    ?execution config:sources ?sourceElement .
    ?sourceElement (rdf:rest*/rdf:first) ?source .
    ?execution config:queryString ?queryString .
}
  `, {
    sources: [
      pipelineDescriptionStore
    ]
  })

  const queryInfo: {query: string, sources: any[]} = await new Promise(
    (resolve, reject) => {
      let queryString: string | undefined = undefined
      let sources: any[] | undefined = undefined;
      queryInfoStream.on('data', (data) => {
        const queryTerm = data.get('queryString');
        if (queryString === undefined && queryTerm?.value !== undefined) {
          queryString = queryTerm.value;
        }
        if (queryTerm?.value === queryString) {
          const sourceTerm = data.get('source');
          if (!sourceTerm) {
            return;
          }
          if (sources === undefined) {
            sources = [sourceTerm];
            return;
          }
          sources.push(sourceTerm);
        }
      });
      queryInfoStream.on('end', () => {
        if (queryString === undefined) {
          reject(new Error('No query string found in the pipeline description.'));
          return
        }
        if (sources === undefined) {
          reject(new Error('No sources found in the pipeline description.'));
          return
        }
        resolve({ query: queryString, sources: sources });
      });
      queryInfoStream.on('error', (error) => {
        reject(error);
      });
    }
  );
  queryInfoStream.destroy();

  const { staticSources, dynamicSources } = classifySources(pipelineDescriptionStore, queryInfo.sources);

  console.log(`Executing SPARQL SELECT query: ${queryInfo.query}`);
  console.log(`Using static sources: ${JSON.stringify(staticSources)}`);
  if (dynamicSources.length > 0) {
    console.log(`Configuring dynamic sources from SSE endpoints: ${JSON.stringify(dynamicSources)}`);
  }

  const iteratorOptions: {
    seedSources?: string[];
    distinct: boolean;
  } = {
    distinct: true,
  };
  if (staticSources.length > 0) {
    iteratorOptions.seedSources = staticSources;
  }
  const querySourceIterator = new QuerySourceIterator(iteratorOptions);

  for (const dynamicSource of dynamicSources) {
    void maintainDynamicSource(dynamicSource, querySourceIterator);
  }

  const queryEngine = new QueryEngineInc();
  const bindingsStream = await queryEngine.queryBindings(queryInfo.query, {
    sources: [querySourceIterator as any],
    fetch: customFetch
  });

  const materializedView: Map<string,{bindings: any, count: number}> = new Map();

  // Create SSE manager for broadcasting updates
  const sseManager = new SSEConnectionManager();

  bindingsStream.on('data', (bindings: any) => {
    const key = bindings.toString();
    if (isAddition(bindings)) {
      if (materializedView.has(key)) {
        materializedView.get(key)!.count++;
      } else {
        materializedView.set(key, { bindings: bindings, count: 1 });
      }

      // Broadcast only the added binding to all SSE connections
      sseManager.broadcast("addition", bindingToSparqlJson(bindings));
    } else {
      if (materializedView.has(key)) {
        const existingElement = materializedView.get(key)!;
        existingElement.count--;
        if (existingElement.count <= 0) {
          materializedView.delete(key);
        }

        // Broadcast only the removed binding to all SSE connections
        sseManager.broadcast("removal", bindingToSparqlJson(bindings));
      } else {
        throw new Error('Received a removal for a binding that was not in the materialized view:' + key);
      }
    }
  });
  bindingsStream.on('end', () => {
    console.log('Query execution finished.');
  });
  bindingsStream.on('error', (error) => {
    // Log original error and wrap in a new Error with message
    console.error('Error during query execution:', error);
    // Do not throw here to avoid crashing the server; keep running
  });

  const server = http.createServer((req, res) => {
    console.log(`Received request: ${req.method} ${req.url}`);
    if (req.method === "GET" && req.url === "/") {
      res.writeHead(200, { "Content-Type": "application/sparql-results+json" });
      const sparqlJson = materializedViewToSparqlJson(materializedView);
      res.end(JSON.stringify(sparqlJson, null, 2));
    } else if (req.method === "GET" && req.url === "/events") {
      // Handle SSE connection
      res.writeHead(200, {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "Cache-Control"
      });

      // Add this connection to the SSE manager
      sseManager.addConnection(res);

      // Send initial data immediately
      sseManager.sendToConnection(res, "init", materializedViewToSparqlJson(materializedView));

      // Keep connection alive with periodic heartbeat
      const heartbeat = setInterval(() => {
        sseManager.sendToConnection(res, "heartbeat", { timestamp: Date.now() });
      }, 30000);

      req.on('close', () => {
        clearInterval(heartbeat);
      });
    } else {
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("Not found");
    }
  });

  server.listen(8080, async () => {
    console.log("SPARQL SELECT result server running at http://localhost:8080/");
    console.log("Server-Sent Events available at http://localhost:8080/events");

    // Register with the aggregator after server starts
    await registerWithAggregator();
  });
}

function classifySources(store: Store, sourceTerms: any[]): { staticSources: string[]; dynamicSources: DynamicSourceConfig[] } {
  const staticSources: string[] = [];
  const dynamicSources: DynamicSourceConfig[] = [];

  for (const term of sourceTerms ?? []) {
    if (!term) {
      continue;
    }

    if (term.termType === 'BlankNode' && store.countQuads(term, RDF_TYPE, SPARQL_RESULT_SOURCE_CLASS, null) > 0) {
      const endpointQuad = store.getQuads(term, SPARQL_RESULT_PREDICATE, null, null)[0];
      const variablesQuad = store.getQuads(term, EXTRACT_VARIABLES_PREDICATE, null, null)[0];

      const endpoint = endpointQuad?.object?.value;
      const variables = variablesQuad ? readRdfList(store, variablesQuad.object)
        .map(variableTerm => variableTerm?.value)
        .filter((value): value is string => typeof value === "string" && value.length > 0) : [];

      if (endpoint) {
        dynamicSources.push({ endpoint, variables });
      } else {
        console.warn("Dynamic source is missing sparqlQueryResult endpoint definition.");
      }
      continue;
    }

    const staticValue = getSourceValue(term);
    if (staticValue !== undefined) {
      staticSources.push(staticValue);
    } else {
      console.warn(`Unable to interpret source term ${JSON.stringify(term)}`);
    }
  }

  return { staticSources, dynamicSources };
}

function getSourceValue(term: any): string | undefined {
  if (!term) {
    return undefined;
  }
  if (term.termType === 'Literal' || term.termType === 'NamedNode') {
    return term.value;
  }
  return undefined;
}

function readRdfList(store: Store, head: any): any[] {
  const values: any[] = [];
  if (!head) {
    return values;
  }

  let current: any | undefined = head;
  const visited = new Set<string>();

  while (current && !(current.termType === 'NamedNode' && current.value === RDF_NIL.value)) {
    const key = `${current.termType}:${current.value ?? ''}`;
    if (visited.has(key)) {
      break;
    }
    visited.add(key);

    const firstQuad = store.getQuads(current, RDF_FIRST, null, null)[0];
    if (!firstQuad) {
      break;
    }
    values.push(firstQuad.object);

    const restQuad = store.getQuads(current, RDF_REST, null, null)[0];
    if (!restQuad) {
      break;
    }
    current = restQuad.object;
  }

  return values;
}

async function maintainDynamicSource(config: DynamicSourceConfig, iterator: QuerySourceIterator): Promise<void> {
  while (true) {
    try {
      console.log(`Connecting to dynamic source stream at ${config.endpoint} (variables: ${config.variables.join(", ") || "none"})`);
      await consumeDynamicSourceStream(config, iterator);
      console.log(`SSE stream at ${config.endpoint} ended, will attempt to reconnect in 5 seconds.`);
    } catch (error) {
      console.error(`Error while consuming SSE stream at ${config.endpoint}:`, error);
    }
    await delay(5000);
  }
}

async function consumeDynamicSourceStream(config: DynamicSourceConfig, iterator: QuerySourceIterator): Promise<void> {
  const response = await customFetch(config.endpoint, {
    headers: {
      "Accept": "text/event-stream",
    },
  });

  if (!response.ok || !response.body) {
    throw new Error(`Failed to connect to SSE stream at ${config.endpoint}: ${response.status} ${response.statusText}`);
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8");
  let buffer = "";

  while (true) {
    const { value, done } = await reader.read();
    if (done) {
      break;
    }
    buffer += decoder.decode(value, { stream: true });
    buffer = buffer.replace(/\r\n/gu, "\n");

    let separatorIndex = buffer.indexOf("\n\n");
    while (separatorIndex !== -1) {
      const rawEvent = buffer.slice(0, separatorIndex);
      buffer = buffer.slice(separatorIndex + 2);
      const event = parseSseEvent(rawEvent);
      if (event) {
        handleSseEvent(event, config, iterator);
      }
      separatorIndex = buffer.indexOf("\n\n");
    }
  }
}

interface ParsedSseEvent {
  event: string;
  data: string;
}

function parseSseEvent(raw: string): ParsedSseEvent | null {
  const lines = raw.split("\n");
  let eventName = "message";
  const dataLines: string[] = [];

  for (const originalLine of lines) {
    const line = originalLine.trimEnd();
    if (line.length === 0 || line.startsWith(":")) {
      continue;
    }
    if (line.startsWith("event:")) {
      eventName = line.slice(6).trimStart();
      continue;
    }
    if (line.startsWith("data:")) {
      let dataValue = line.slice(5);
      if (dataValue.startsWith(" ")) {
        dataValue = dataValue.slice(1);
      }
      dataLines.push(dataValue);
      continue;
    }
  }

  if (dataLines.length === 0) {
    return null;
  }
  return { event: eventName, data: dataLines.join("\n") };
}

function handleSseEvent(event: ParsedSseEvent, config: DynamicSourceConfig, iterator: QuerySourceIterator): void {
  if (!event.data) {
    return;
  }

  if (event.event === "heartbeat") {
    return;
  }

  let payload: any;
  try {
    payload = JSON.parse(event.data);
  } catch (error) {
    console.error(`Failed to parse SSE event data from ${config.endpoint}:`, error);
    return;
  }

  const sources =
    event.event === "init"
      ? extractSourcesFromInitPayload(payload, config.variables)
      : extractSourcesFromBindingPayload(payload, config.variables);

  if (sources.length === 0) {
    return;
  }

  if (event.event === "removal") {
    for (const source of sources) {
      try {
        iterator.removeSource(source);
      } catch (error) {
        console.error(`Failed to remove dynamic source ${source}:`, error);
      }
    }
  } else if (event.event === "addition" || event.event === "init") {
    for (const source of sources) {
      try {
        iterator.addSource(source);
      } catch (error) {
        console.error(`Failed to add dynamic source ${source}:`, error);
      }
    }
  } else {
    console.warn(`Received unsupported SSE event "${event.event}" from ${config.endpoint}`);
  }
}

function extractSourcesFromBindingPayload(payload: any, variables: string[]): string[] {
  const bindingObject = payload?.binding ?? payload;
  if (!bindingObject || typeof bindingObject !== "object") {
    return [];
  }

  return collectSourcesFromBindingObject(bindingObject, variables);
}

function extractSourcesFromInitPayload(payload: any, variables: string[]): string[] {
  const bindings = payload?.results?.bindings;
  if (!Array.isArray(bindings)) {
    return [];
  }
  const sources: string[] = [];
  for (const binding of bindings) {
    sources.push(...collectSourcesFromBindingObject(binding, variables));
  }
  return sources;
}

function collectSourcesFromBindingObject(bindingObject: any, variables: string[]): string[] {
  if (!bindingObject || typeof bindingObject !== "object") {
    return [];
  }

  const sourceValues: string[] = [];
  const variableNames = variables.length > 0 ? variables : Object.keys(bindingObject);

  for (const variableName of variableNames) {
    const binding = bindingObject[variableName];
    if (!binding || typeof binding !== "object") {
      continue;
    }
    if (binding.type === "uri" && typeof binding.value === "string" && binding.value.length > 0) {
      sourceValues.push(binding.value);
    }
  }

  return sourceValues;
}

function delay(ms: number): Promise<void> {
  return new Promise(resolve => {
    setTimeout(resolve, ms);
  });
}

// Function to convert materialized view to SPARQL JSON format
function materializedViewToSparqlJson(materializedView: Map<string,{bindings: any, count: number}>) {
  const variablesSet: Set<string> = new Set();
  const results: {[variableName: string]: {type: string, value: string, datatype?: string, "xml:lang"?: string }}[] = [];

  for (const materializedElement of materializedView.values()) {
    for (const variable of materializedElement.bindings.keys()) {
      variablesSet.add(variable.value);
    }
    let result: {[variableName: string]: {type: string, value: string, datatype?: string, "xml:lang"?: string }} = {};
    for (const [variable, value] of materializedElement.bindings) {
      if (value.termType === 'Literal') {
        result[variable.value] = {
          type: 'literal',
          value: value.value
        };
        if (value.datatype) {
          result[variable.value].datatype = value.datatype.value;
        }
        if (value.language) {
          result[variable.value]["xml:lang"] = value.language;
        }
      } else if (value.termType === 'NamedNode') {
        result[variable.value] = {
          type: 'uri',
          value: value.value
        };
      } else if (value.termType === 'BlankNode') {
        result[variable.value] = {
          type: 'bnode',
          value: value.value
        };
      }
    }
    for (let i = 0; i < materializedElement.count; i++) {
      results.push(result);
    }
  }

  return {
    head: { vars: [...variablesSet.keys()] },
    results: { bindings: results },
  };
}

// Function to convert a single binding to SPARQL JSON format
function bindingToSparqlJson(bindings: any) {
  const variablesSet: Set<string> = new Set();
  let result: {[variableName: string]: {type: string, value: string, datatype?: string, "xml:lang"?: string }} = {};

  for (const variable of bindings.keys()) {
    variablesSet.add(variable.value);
  }

  for (const [variable, value] of bindings) {
    if (value.termType === 'Literal') {
      result[variable.value] = {
        type: 'literal',
        value: value.value
      };
      if (value.datatype) {
        result[variable.value].datatype = value.datatype.value;
      }
      if (value.language) {
        result[variable.value]["xml:lang"] = value.language;
      }
    } else if (value.termType === 'NamedNode') {
      result[variable.value] = {
        type: 'uri',
        value: value.value
      };
    } else if (value.termType === 'BlankNode') {
      result[variable.value] = {
        type: 'bnode',
        value: value.value
      };
    }
  }

  return {
    head: { vars: [...variablesSet.keys()] },
    binding: result
  };
}

main();
