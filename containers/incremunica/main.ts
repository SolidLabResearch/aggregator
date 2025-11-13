import { QueryEngine } from '@comunica/query-sparql';
import { QueryEngine as QueryEngineInc } from '@incremunica/query-sparql-incremental';
import { isAddition } from '@incremunica/user-tools';
import { Store, Parser, DataFactory } from 'n3';
import http from "http";
import { URL } from "url";
import {EventEmitter} from "node:events";

class SSEConnectionManager {
  private connections: Map<http.ServerResponse, NodeJS.Timeout> = new Map();

  addConnection(res: http.ServerResponse): void {
    console.log('New SSE connection established');
    const heartbeat = setInterval(() => {
      this.sendToConnection(res, "heartbeat", { timestamp: Date.now() });
    }, 30000);
    this.connections.set(res, heartbeat);
    res.on('close', () => {
      this.removeConnection(res);
    });
  }

  removeConnection(res: http.ServerResponse): boolean {
    console.log('SSE connection closed');
    const heartbeat = this.connections.get(res);
    if (heartbeat) {
      clearInterval(heartbeat);
    }
    return this.connections.delete(res);
  }

  broadcast(event: string, data?: any): void {
    console.log(`Broadcasting event: ${event}`);
    let message = `event: ${event}\n`
    if (data) {
      message += `data: ${JSON.stringify(data)}\n`;
    }
    message += `\n`;
    for (const connection of this.connections) {
      try {
        connection[0].write(message);
      } catch (error) {
        this.removeConnection(connection[0])
      }
    }
  }

  sendToConnection(res: http.ServerResponse, event: string, data?: any): void {
    console.log(`Sending event to connection: ${event}`);
    let message = `event: ${event}\n`
    if (data) {
      message += `data: ${JSON.stringify(data)}\n`;
    }
    message += `\n`;
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

const registeredSources: Map<string, {
  issuer: string;
  derivation_resource_id: string;
}> = new Map();
// Create custom fetch function that uses the proxy's /fetch endpoint
async function customFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const originalUrl = input.toString();

  // Prepare the request payload for the proxy
  const fetchRequest = {
    url: originalUrl,
    method: init?.method?.toUpperCase() || 'GET',
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

  if (
    !registeredSources.has(originalUrl) &&
    response.headers.get("X-Derivation-Issuer") &&
    response.headers.get("X-Derivation-Resource-Id")
  ) {
    registeredSources.set(originalUrl, {
      issuer: response.headers.get("X-Derivation-Issuer")!,
      derivation_resource_id: response.headers.get("X-Derivation-Resource-Id")!
    });
    await Promise.all([
      patchEndpointSources("/"),
      patchEndpointSources("/events")
    ]);
  }

  return response;
}

// Function to register an endpoint with the aggregator
async function registerEndpointWithAggregator(endpoint: string, description: string, scopes: string[] = ["read"]): Promise<void> {
  const registrationData: any = {
    pod_name: POD_NAME,
    pod_ip: POD_IP,
    port: SERVICE_PORT,
    endpoint: endpoint,
    scopes: scopes,
    description: description,
  };

  try {
    console.log(`📝 Registering endpoint ${endpoint} with aggregator at ${REGISTRATION_URL}`);
    console.log(`   Pod: ${POD_NAME}, IP: ${POD_IP}, Port: ${SERVICE_PORT}`);
    console.log(`   Description: ${description}`);
    if (registrationData.sources) {
      console.log(`   Sources[${registrationData.sources.length}]: ${registrationData.sources.join(', ')}`);
    }

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

async function patchEndpointSources(endpoint: string): Promise<boolean> {
  const sources = [];
  for (const [sourceUrl, sourceInfo] of registeredSources) {
    sources.push({
      issuer: sourceInfo.issuer,
      derivation_resource_id: sourceInfo.derivation_resource_id
    });
  }
  const payload = {
    pod_name: POD_NAME,
    endpoint: endpoint,
    sources: sources,
  };
  try {
    console.log(`✏️ Patching sources for ${endpoint} (n=${sources.length})`);
    const res = await fetch(REGISTRATION_URL, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const txt = await res.text();
      console.error(`❌ Failed to patch sources: ${res.status} ${txt}`);
      return false;
    }
    console.log(`✅ Sources updated for ${endpoint}`);
    return true;
  } catch (e) {
    console.error(`❌ Error patching sources for ${endpoint}:`, e);
    return false;
  }
}

// Function to register all endpoints with the aggregator
async function registerWithAggregator(): Promise<void> {
  console.log('🌐 Registering all endpoints with aggregator...');

  // Register the main SPARQL results endpoint
  await registerEndpointWithAggregator(
    "/",
    "SPARQL SELECT incremental query service - JSON results",
    ["urn:example:css:modes:read"]
  );

  // Register the server-sent events endpoint
  await registerEndpointWithAggregator(
    "/events",
    "SPARQL SELECT incremental query service - Real-time SSE stream",
    ["urn:example:css:modes:continuous:read"]
  );

  console.log('✅ All endpoints registered with aggregator');
}

class UpToDateTimeout {
  private readonly interval: number;
  private readonly upToDateCallback: () => void = () => {};
  private timeout: NodeJS.Timeout | undefined;

  constructor(interval: number = 1000, upToDateCallback?: () => void) {
    this.interval = interval;
    if (upToDateCallback) {
      this.upToDateCallback = upToDateCallback;
    }
    this.reset();
  }

  reset(): void {
    if (this.timeout) {
      this.timeout.close();
    }
    this.timeout = setTimeout(() => {
      this.timeout = undefined;
      this.upToDateCallback();
    }, this.interval);
  }

  isUpToDate(): boolean {
    return this.timeout === undefined;
  }
}

async function main() {
  let server: http.Server;
  await new Promise((resolve, reject) => {
    server = http.createServer((req, res) => {
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

        sseManager.addConnection(res);

        sseManager.sendToConnection(res, "init", materializedViewToSparqlJson(materializedView));
        if (upToDateTimeout.isUpToDate()) {
          sseManager.sendToConnection(res, "up-to-date", { timestamp: Date.now() });
        }

        req.on('close', () => {
          sseManager.removeConnection(res);
        });
      } else {
        res.writeHead(404, { "Content-Type": "text/plain" });
        res.end("Not found");
      }
    });

    server.listen(8080, async () => {
      console.log("SPARQL SELECT result server running at http://localhost:8080/");
      console.log("Server-Sent Events available at http://localhost:8080/events");

      // Register with the aggregator after server starts, include sources
      await registerWithAggregator();

      resolve(undefined);
    });
  });

  const pipelineDescription = process.env.PIPELINE_DESCRIPTION;
  if (pipelineDescription === undefined) {
    throw new Error('Environment variable PIPELINE_DESCRIPTION is not set. Please provide a valid pipeline description.');
  }
  console.log(pipelineDescription)
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
          resolve();
        }
      });
    }
  );

  const queryInfoStream = await pipelineParsingEngine.queryBindings(`
PREFIX fno: <https://w3id.org/function/ontology#>
PREFIX trans: <http://localhost:5000/config/transformations#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>

SELECT ?queryString ?source ?endpoint ?variable WHERE {
    ?execution a fno:Execution .
    ?execution fno:executes trans:SPARQLEvaluation .
    ?execution trans:queryString ?queryString .
    ?execution trans:sources ?sourceElement .
    ?sourceElement (rdf:rest*/rdf:first) ?source .
    OPTIONAL {
        ?source a trans:SPARQLQueryResultSource .
        ?source trans:sparqlQueryResult ?endpoint .
        ?source trans:extractVariables ?variablesElement .
        ?variablesElement (rdf:rest*/rdf:first) ?variable .
    }
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
      const dynamicSourceMap: Map<string, { endpoint: string, variables: string[] }> = new Map();
      queryInfoStream.on('data', (data) => {
        const queryTerm = data.get('queryString');
        if (queryString === undefined && queryTerm?.value !== undefined) {
          queryString = queryTerm.value;
        }
        if (queryTerm?.value === queryString) {
          const sourceNode: any = data.get('source');
          if (!sourceNode) {
            return;
          }

          const endpointTerm: any = data.get('endpoint');
          const variableTerm: any = data.get('variable');
          let sourceTerm: any = sourceNode;
          if (endpointTerm) {
            const key = `${sourceNode.termType}:${sourceNode.value ?? ''}`;
            let entry = dynamicSourceMap.get(key);
            if (!entry) {
              entry = { endpoint: endpointTerm.value, variables: [] };
              dynamicSourceMap.set(key, entry);
              if (!sources) {
                sources = [ entry ];
              } else {
                sources.push(entry);
              }
            }
            if (variableTerm?.value && !entry.variables.includes(variableTerm.value)) {
              entry.variables.push(variableTerm.value);
            }
          } else {
            if (!sources) {
              sources = [ sourceTerm ];
            } else {
              sources.push(sourceTerm);
            }
            return;
          }
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

  const sources = await getSources(queryInfo.sources);
  if (sources.length === 0) {
    throw new Error('No valid sources found in the pipeline description.');
  }

  const queryEngine = new QueryEngineInc();
  const bindingsStream = await queryEngine.queryBindings(queryInfo.query, {
    // @ts-ignore
    sources: sources,
    fetch: customFetch,
    deferredEvaluationTrigger: new EventEmitter(),
  });

  const materializedView: Map<string,{bindings: any, count: number}> = new Map();

  // Create SSE manager for broadcasting updates
  const sseManager = new SSEConnectionManager();
  const upToDateTimeout = new UpToDateTimeout(1000, () => {
    sseManager.broadcast("up-to-date", { timestamp: Date.now() });
  });

  bindingsStream.on('data', (bindings: any) => {
    upToDateTimeout.reset();
    const key = bindings.toString();
    if (isAddition(bindings)) {
      if (materializedView.has(key)) {
        materializedView.get(key)!.count++;
      } else {
        materializedView.set(key, { bindings: bindings, count: 1 });
      }

      sseManager.broadcast("addition", bindingToSparqlJson(bindings));
    } else {
      if (materializedView.has(key)) {
        const existingElement = materializedView.get(key)!;
        existingElement.count--;
        if (existingElement.count <= 0) {
          materializedView.delete(key);
        }

        sseManager.broadcast("deletion", bindingToSparqlJson(bindings));
      } else {
        throw new Error('Received a deletion for a binding that was not in the materialized view:' + key);
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

  await new Promise(resolve => server.on("close", resolve));
}

async function getSources(sourceTerms: any[]): Promise<string[]> {
  const sources: Set<string> = new Set();
  const promises: Promise<string[]>[] = [];

  for (const term of sourceTerms ?? []) {
    if (!term) {
      continue;
    }

    if (term.endpoint) {
      const vars = Array.isArray(term.variables) ? term.variables : [];
      console.log(`Interpreted dynamic SPARQL source: endpoint=${term.endpoint}, variables=[${vars.join(", ")}]`);
      promises.push(customFetch(term.endpoint).then(response => {
        if (!response.ok) {
          throw new Error(`Failed to fetch from SPARQL endpoint ${term.endpoint}: ${response.status} ${response.statusText}`);
        }
        return response.json()
      }).then((json): string[] => {
        const endpointSources: string[] = [];
        json.results.bindings.forEach((binding: any) => {
          endpointSources.push(...collectSourcesFromBindingObject(binding, vars));
        });
        console.log(`Collected ${endpointSources.length} sources from endpoint ${term.endpoint}`);
        return endpointSources;
      }));
      continue;
    }

    const staticValue = getSourceValue(term);
    if (staticValue !== undefined) {
      console.log(`Interpreted static source: ${staticValue}`);
      sources.add(staticValue);
    } else {
      console.warn(`Unable to interpret source term ${JSON.stringify(term)}`);
    }
  }

  let awaitedSources = await Promise.all(promises);
  for (const awaitedSourceList of awaitedSources) {
    for (const source of awaitedSourceList) {
      sources.add(source);
    }
  }
  console.log(`Total sources collected: ${sources.size}`);

  return [...sources];
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

function collectSourcesFromBindingObject(bindingObject: any, variables: string[]): string[] {
  if (!bindingObject || typeof bindingObject !== "object") {
    return [];
  }

  const sourceValues: string[] = [];
  const variableNames = variables.length > 0 ? variables : Object.keys(bindingObject);
  const namesNormalized = variableNames.map(v => typeof v === 'string' && v.startsWith('?') ? v.slice(1) : v);

  for (const variableName of namesNormalized) {
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

function bindingToSparqlJson(bindings: any) {
  let result: {[variableName: string]: {type: string, value: string, datatype?: string, "xml:lang"?: string }} = {};

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
    bindings: [result]
  };
}

main()
  .then(() => {
    console.error('Error: Incremunica client closed.');
    process.exit(1);
  })
  .catch((error) => {
    console.error('Error starting Incremunica client:', error);
    process.exit(1);
  });
