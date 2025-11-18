import { QueryEngine } from '@comunica/query-sparql';
import { QueryEngine as QueryEngineInc } from '@incremunica/query-sparql-incremental';
import { isAddition, QuerySourceIterator } from '@incremunica/user-tools';
import { Store, Parser } from 'n3';
import http from "http";
import { URL } from "url";
import {EventEmitter} from "node:events";
import { logger } from './logger';

class SSEConnectionManager {
  private connections: Map<http.ServerResponse, NodeJS.Timeout> = new Map();

  addConnection(res: http.ServerResponse): void {
    logger.info('New SSE connection established');
    const heartbeat = setInterval(() => {
      this.sendToConnection(res, "heartbeat", { timestamp: Date.now() });
    }, 30000);
    this.connections.set(res, heartbeat);
    res.on('close', () => {
      this.removeConnection(res);
    });
  }

  removeConnection(res: http.ServerResponse): boolean {
    logger.info('SSE connection closed');
    const heartbeat = this.connections.get(res);
    if (heartbeat) {
      clearInterval(heartbeat);
    }
    return this.connections.delete(res);
  }

  broadcast(event: string, data?: any): void {
    logger.debug({ event }, 'Broadcasting event');
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
    logger.debug({ event }, 'Sending event to connection');
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
// Build a list of candidate aggregator registration URLs. Do not perform any network I/O here.
function resolveRegistrationCandidates(): string[] {
  const fromEnv = process.env.AGGREGATOR_URL || process.env.REGISTRATION_URL;
  if (fromEnv && typeof fromEnv === 'string' && fromEnv.trim().length > 0) {
    return [normalizeBaseUrl(fromEnv)];
  }
  const inK8s = !!process.env.KUBERNETES_SERVICE_HOST || !!process.env.KUBERNETES_SERVICE_PORT;
  if (inK8s) {
    // Prefer in-cluster Service DNS, then Docker host name, then Docker bridge gateway.
    return [
      'http://aggregator-registration:4449/',
      'http://host.docker.internal:4449/',
      'http://172.17.0.1:4449/'
    ];
  }
  // Local default when running outside Kubernetes.
  return ['http://127.0.0.1:4449/'];
}

function normalizeBaseUrl(base: string): string {
  // Ensure it has protocol and trailing slash
  let url = base.trim();
  if (!/^https?:\/\//i.test(url)) {
    url = `http://${url}`;
  }
  if (!url.endsWith('/')) url += '/';
  return url;
}

const REGISTRATION_CANDIDATES = resolveRegistrationCandidates();
let lastSuccessfulRegistrationUrl: string | undefined;

const POD_NAME = process.env.HOSTNAME || "incremunica-pod";
const POD_IP = process.env.POD_IP || "127.0.0.1";
const SERVICE_PORT = 8080;

const proxyUrl = process.env.http_proxy || process.env.HTTP_PROXY;
// Only enforce proxy presence when executing the main program, not on import for tests.
if (require.main === module && proxyUrl === undefined) {
  logger.warn('[incremunica] PROXY_URL (http_proxy/HTTP_PROXY) not set, falling back to direct fetch.');
}

const registeredSources: Map<string, {
  issuer: string;
  derivation_resource_id: string;
}> = new Map();
// Create custom fetch function that uses the proxy's /fetch endpoint
async function customFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const originalUrl = input.toString();

  // If no proxy configured, fall back to direct fetch.
  if (!proxyUrl) {
    logger.trace({ url: originalUrl }, 'Direct fetch (no proxy)');
    return fetch(input as any, init);
  }

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

  logger.info({
    has: registeredSources.has(originalUrl),
    Issuer: response.headers.get("X-Derivation-Issuer"),
    ResourceId: response.headers.get("X-Derivation-Resource-Id")
  }, 'fetch');
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

// Small helper: do a fetch with a timeout
async function fetchWithTimeout(url: string, init: RequestInit, timeoutMs: number): Promise<Response> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(id);
  }
}

// Try registration against multiple candidates until one succeeds (network-level). Keep the last successful URL for subsequent calls.
async function fetchRegistration(method: 'POST' | 'PATCH' | 'PUT' | 'DELETE', body: any, timeoutMs = 2500): Promise<Response | null> {
  const payload = JSON.stringify(body ?? {});
  const headers = { 'Content-Type': 'application/json' } as any;
  const candidates = lastSuccessfulRegistrationUrl ? [ lastSuccessfulRegistrationUrl, ...REGISTRATION_CANDIDATES.filter(c => c !== lastSuccessfulRegistrationUrl) ] : REGISTRATION_CANDIDATES;

  for (const base of candidates) {
    const url = base; // registration handler matches all paths; root is sufficient
    try {
      logger.debug({ url, method }, 'Attempting aggregator registration');
      const res = await fetchWithTimeout(url, { method, headers, body: payload }, timeoutMs);
      // If we reached a server, return it regardless of status (caller decides). Cache base.
      lastSuccessfulRegistrationUrl = base;
      if (res.ok) {
        logger.info({ url: base }, 'Aggregator registration endpoint selected');
      } else {
        logger.warn({ url: base, status: res.status }, 'Aggregator registration responded with non-OK');
      }
      return res;
    } catch (err: any) {
      const msg = typeof err?.message === 'string' ? err.message : String(err);
      logger.warn({ url, err: msg }, 'Registration attempt failed');
      continue;
    }
  }
  return null;
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
    logger.info({ endpoint, scopes, description }, 'Registering endpoint');
    const response = await fetchRegistration("POST", registrationData);
    if (!response) {
      logger.error({ endpoint }, 'Failed registering endpoint: no aggregator reachable');
      return;
    }
    if (response.ok) {
      const result = await response.json();
      logger.info({ endpoint, external_url: result.external_url, actor_id: result.actor_id }, 'Endpoint registered');
      return result.actor_id;
    } else {
      const errorText = await response.text();
      logger.error({ endpoint, status: response.status, errorText }, 'Failed registering endpoint');
    }
  } catch (error) {
    logger.error({ endpoint, error: (error as any)?.toString?.() ?? String(error) }, 'Error registering endpoint');
  }
}

async function patchEndpointSources(endpoint: string): Promise<boolean> {
  const sources = [];
  for (const [, sourceInfo] of registeredSources) {
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
    logger.debug({ endpoint, count: sources.length }, 'Patching sources');
    const res = await fetchRegistration("PATCH", payload);
    if (!res) {
      logger.error({ endpoint }, 'Patch sources failed: no aggregator reachable');
      return false;
    }
    if (!res.ok) {
      const txt = await res.text();
      logger.error({ endpoint, status: res.status, txt }, 'Patch sources failed');
      return false;
    }
    logger.info({ endpoint, count: sources.length }, 'Sources patched');
    return true;
  } catch (e) {
    logger.error({ endpoint, error: e }, 'Error patching sources');
    return false;
  }
}

// Function to register all endpoints with the aggregator
async function registerWithAggregator(): Promise<void> {
  logger.info('Registering all endpoints with aggregator');

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

  logger.info('All endpoints registered with aggregator');
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
      clearTimeout(this.timeout as any);
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
  const materializedView: Map<string,{bindings: any, count: number}> = new Map();
  let server: http.Server;
  const deferredEvaluationTrigger = new EventEmitter();
  await new Promise((resolve) => {
    server = http.createServer((req, res) => {
      logger.info({ method: req.method, url: req.url }, 'Incoming request');
      if (req.method === "GET" && req.url === "/") {
        res.writeHead(200, { "Content-Type": "application/sparql-results+json" });
        deferredEvaluationTrigger.emit("update");
        const sparqlJson = materializedViewToSparqlJson(materializedView);
        res.end(JSON.stringify(sparqlJson, null, 2));
      } else if (req.method === "GET" && req.url === "/events") {
        // Handle SSE connection
        res.writeHead(200, {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
          "Connection": "keep-alive"
        });
        const timeout = setInterval(() => {
          deferredEvaluationTrigger.emit("update");
        }, 1000);

        sseManager.addConnection(res);

        sseManager.sendToConnection(res, "init", materializedViewToSparqlJson(materializedView));
        if (upToDateTimeout.isUpToDate()) {
          sseManager.sendToConnection(res, "up-to-date", { timestamp: Date.now() });
        }

        req.on('close', () => {
          timeout.close();
          sseManager.removeConnection(res);
        });
      } else {
        res.writeHead(404, { "Content-Type": "text/plain" });
        res.end("Not found");
      }
    });

    server.listen(8080, async () => {
      logger.info('SPARQL SELECT result server running at http://localhost:8080/');
      logger.info('Server-Sent Events available at http://localhost:8080/events');

      // Register with the aggregator after server starts, include sources
      await registerWithAggregator();

      resolve(undefined);
    });
  });

  const pipelineDescription = process.env.PIPELINE_DESCRIPTION;
  if (pipelineDescription === undefined) {
    throw new Error('Environment variable PIPELINE_DESCRIPTION is not set. Please provide a valid pipeline description.');
  }
  logger.debug({ pipelineDescriptionLength: pipelineDescription.length }, 'Parsing pipeline description')
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

  const sourceIterator = await getSources(queryInfo.sources);

  const queryEngine = new QueryEngineInc();
  const bindingsStream = await queryEngine.queryBindings(queryInfo.query, {
    // @ts-ignore
    sources: [sourceIterator],
    fetch: customFetch,
    deferredEvaluationTrigger: deferredEvaluationTrigger,
  });

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
    logger.info('Query execution finished');
  });
  bindingsStream.on('error', (error) => {
    logger.error({ error }, 'Error during query execution');
  });

  await new Promise(resolve => server.on("close", resolve));
}

async function getSources(sourceTerms: any[], pollIntervalMs: number = 5000): Promise<QuerySourceIterator> {
  // Collect static sources and dynamic endpoint descriptors
  const staticSources: Set<string> = new Set();
  const dynamicEndpoints: { endpoint: string; variables: string[] }[] = [];

  for (const term of sourceTerms ?? []) {
    if (!term) continue;
    if (term.endpoint) {
      const vars = Array.isArray(term.variables) ? term.variables : [];
      logger.debug({ endpoint: term.endpoint, variables: vars }, 'Dynamic SPARQL source interpreted');
      dynamicEndpoints.push({ endpoint: term.endpoint, variables: vars });
      continue;
    }
    const staticValue = getSourceValue(term);
    if (staticValue !== undefined) {
      logger.debug({ source: staticValue }, 'Static source interpreted');
      staticSources.add(staticValue);
    } else {
      logger.warn({ term }, 'Unable to interpret source term');
    }
  }

  async function fetchEndpointSources(descriptor: { endpoint: string; variables: string[] }): Promise<string[]> {
    try {
      const response = await customFetch(descriptor.endpoint);
      if (!response.ok) {
        throw new Error(`Failed to fetch from SPARQL endpoint ${descriptor.endpoint}: ${response.status} ${response.statusText}`);
      }
      const json = await response.json();
      const endpointSources: string[] = [];
      if (json?.results?.bindings && Array.isArray(json.results.bindings)) {
        json.results.bindings.forEach((binding: any) => {
          endpointSources.push(...collectSourcesFromBindingObject(binding, descriptor.variables));
        });
      }
      logger.info({ count: endpointSources.length, endpoint: descriptor.endpoint }, 'Sources collected from endpoint');
      return endpointSources;
    } catch (e) {
      logger.error({ endpoint: descriptor.endpoint, error: e }, 'Dynamic sources fetch error');
      return [];
    }
  }

  // Initial dynamic source collection
  const initialDynamicSourcesLists = await Promise.all(dynamicEndpoints.map(d => fetchEndpointSources(d)));
  const initialDynamicCombined: string[] = [];
  for (const list of initialDynamicSourcesLists) {
    for (const s of list) initialDynamicCombined.push(s);
  }

  // Dynamic refcounts across all dynamic endpoints
  const dynamicRefCounts: Map<string, number> = new Map();
  initialDynamicSourcesLists.forEach(list => {
    for (const s of list) {
      dynamicRefCounts.set(s, (dynamicRefCounts.get(s) ?? 0) + 1);
    }
  });

  logger.info({ static: staticSources.size, dynamicSeed: initialDynamicCombined.length }, 'Initial sources collected');

  // Create iterator with only static seed sources
  const querySourceIterator = new QuerySourceIterator({
    seedSources: [...staticSources],
    distinct: true,
  });

  // Add initial dynamic sources explicitly so removals emit events
  for (const [source] of dynamicRefCounts.entries()) {
    if (!staticSources.has(source)) {
      try {
        querySourceIterator.addSource(source);
        logger.debug({ source }, 'Initial dynamic source added');
      } catch (e) {
        logger.error({ source, error: e }, 'Failed adding initial dynamic source');
      }
    }
  }

  // Track previous per endpoint for diffing
  const previousPerEndpoint: Map<string, Set<string>> = new Map();
  dynamicEndpoints.forEach((d, idx) => {
    previousPerEndpoint.set(d.endpoint, new Set(initialDynamicSourcesLists[idx]));
  });

  if (dynamicEndpoints.length > 0) {
    logger.info({ intervalMs: pollIntervalMs, endpoints: dynamicEndpoints.length }, 'Starting dynamic endpoint polling');
  }

  const pollingIntervals: NodeJS.Timeout[] = dynamicEndpoints.map(descriptor => {
    return setInterval(async () => {
      const newList = await fetchEndpointSources(descriptor);
      const newSet = new Set(newList);
      const prevSet = previousPerEndpoint.get(descriptor.endpoint) || new Set<string>();

      // Additions
      for (const value of newSet) {
        if (!prevSet.has(value)) {
          try {
            const prevCount = dynamicRefCounts.get(value) ?? 0;
            dynamicRefCounts.set(value, prevCount + 1);
            if (prevCount === 0 && !staticSources.has(value)) {
              querySourceIterator.addSource(value);
              logger.debug({ source: value, endpoint: descriptor.endpoint }, 'Dynamic source added');
            }
          } catch (e) {
            logger.error({ source: value, error: e }, 'Failed adding source');
          }
        }
      }

      // Removals
      for (const value of prevSet) {
        if (!newSet.has(value)) {
          try {
            const prevCount = dynamicRefCounts.get(value) ?? 0;
            const nextCount = Math.max(0, prevCount - 1);
            dynamicRefCounts.set(value, nextCount);
            if (nextCount === 0 && !staticSources.has(value)) {
              querySourceIterator.removeSource(value);
              logger.debug({ source: value, endpoint: descriptor.endpoint }, 'Dynamic source removed');
            }
          } catch (e) {
            logger.error({ source: value, error: e }, 'Failed removing source');
          }
        }
      }

      previousPerEndpoint.set(descriptor.endpoint, newSet);
    }, pollIntervalMs);
  });

  const clearPolling = () => {
    pollingIntervals.forEach(i => { try { clearInterval(i); } catch { /* ignore */ } });
  };
  process.on('exit', clearPolling);
  process.on('SIGINT', () => { clearPolling(); process.exit(0); });
  process.on('SIGTERM', () => { clearPolling(); process.exit(0); });

  return querySourceIterator;
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
  const namesNormalized = variableNames.map(v => v.startsWith('?') ? v.slice(1) : v);

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

export { getSources, getSourceValue, collectSourcesFromBindingObject, SSEConnectionManager, UpToDateTimeout, materializedViewToSparqlJson, bindingToSparqlJson, logger, customFetch };

if (require.main === module) {
  main()
    .then(() => {
      logger.error('Error: Incremunica client closed.');
      process.exit(1);
    })
    .catch((error) => {
      logger.error({ error }, 'Error starting Incremunica client');
      process.exit(1);
    });
}
