import { QueryEngine } from '@comunica/query-sparql';
import { QueryEngine as QueryEngineInc } from '@incremunica/query-sparql-incremental';
import { isAddition, QuerySourceIterator } from '@incremunica/user-tools';
import { Store, Parser } from 'n3';
import http from "http";
import { URL } from "url";
import {EventEmitter} from "node:events";
import { logger } from './logger';

class SSEConnectionManager {
  private connections: Set<http.ServerResponse> = new Set();
  private pendingUpdates: { additions: any[], deletions: any[] } = { additions: [], deletions: [] };
  private updateBatchTimeout: NodeJS.Timeout | null = null;
  private readonly batchIntervalMs: number = 100;
  private readonly heartbeatIntervalMs: number = 30000;
  private heartbeatTimers: Map<http.ServerResponse, NodeJS.Timeout> = new Map();

  addConnection(res: http.ServerResponse): void {
    logger.info('New SSE connection established');
    this.connections.add(res);
    const hb = setInterval(() => {
      this.sendToConnection(res, 'heartbeat');
    }, this.heartbeatIntervalMs);
    this.heartbeatTimers.set(res, hb);

    res.on('close', () => {
      this.removeConnection(res);
    });
  }

  removeConnection(res: http.ServerResponse): boolean {
    logger.info('SSE connection closed');
    const removed = this.connections.delete(res);
    const timer = this.heartbeatTimers.get(res);
    if (timer) {
      clearInterval(timer as any);
      this.heartbeatTimers.delete(res);
    }
    return removed;
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
        connection.write(message);
      } catch (error) {
        this.removeConnection(connection)
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
      this.removeConnection(res);
    }
  }

  queueUpdate(isAddition: boolean, binding: any): void {
    if (isAddition) {
      this.pendingUpdates.additions.push(binding);
    } else {
      this.pendingUpdates.deletions.push(binding);
    }

    if (this.updateBatchTimeout) {
      clearTimeout(this.updateBatchTimeout);
    }

    this.updateBatchTimeout = setTimeout(() => {
      this.flushUpdates();
    }, this.batchIntervalMs);
  }

  flushUpdates(): void {
    if (this.pendingUpdates.additions.length === 0 && this.pendingUpdates.deletions.length === 0) {
      return;
    }

    const updateData = {
      additions: this.pendingUpdates.additions,
      deletions: this.pendingUpdates.deletions
    };

    this.broadcast('update', updateData);

    this.pendingUpdates = { additions: [], deletions: [] };
    this.updateBatchTimeout = null;
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

// Track registered endpoints for cleanup
type RegisteredEndpoint = { endpoint: string, description: string, scopes: string[] };
const registeredEndpoints: RegisteredEndpoint[] = [];

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
      // Track for cleanup
      registeredEndpoints.push({ endpoint, description, scopes });
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

// Function to deregister an endpoint from the aggregator
async function deregisterEndpointWithAggregator(endpoint: string): Promise<void> {
  const deregData: any = {
    pod_name: POD_NAME,
    pod_ip: POD_IP,
    port: SERVICE_PORT,
    endpoint: endpoint,
  };
  try {
    logger.info({ endpoint }, 'Deregistering endpoint');
    const response = await fetchRegistration("DELETE", deregData);
    if (!response) {
      logger.error({ endpoint }, 'Failed deregistering endpoint: no aggregator reachable');
      return;
    }
    if (response.ok) {
      logger.info({ endpoint }, 'Endpoint deregistered');
    } else {
      const errorText = await response.text();
      logger.error({ endpoint, status: response.status, errorText }, 'Failed deregistering endpoint');
    }
  } catch (error) {
    logger.error({ endpoint, error: (error as any)?.toString?.() ?? String(error) }, 'Error deregistering endpoint');
  }
}

// Function to deregister all endpoints
async function deregisterWithAggregator(): Promise<void> {
  logger.info('Deregistering all endpoints with aggregator');
  await Promise.all(registeredEndpoints.map(e => deregisterEndpointWithAggregator(e.endpoint)));
  logger.info('All endpoints deregistered with aggregator');
}

class UpToDateTimeout {
  private upToDate: boolean = false;
  private interval: number;
  private readonly upToDateCallback: () => void = () => {};
  private timeout: NodeJS.Timeout | undefined;

  constructor(interval: number = 1000, upToDateCallback?: () => void) {
    this.interval = interval;
    if (upToDateCallback) {
      this.upToDateCallback = upToDateCallback;
    }
  }

  reset(interval?: number): void {
    interval = interval ?? this.interval;
    if (this.timeout) {
      clearTimeout(this.timeout as any);
    }
    this.timeout = setTimeout(() => {
      this.timeout = undefined;
      this.upToDate = true;
      this.upToDateCallback();
    }, interval);
    this.upToDate = false;
  }

  isUpToDate(): boolean {
    return this.upToDate;
  }
}

async function main() {
  const materializedView: Map<string,{bindings: any, count: number}> = new Map();
  let server: http.Server;
  const deferredEvaluationTrigger = new EventEmitter();
  const sseManager = new SSEConnectionManager();
  const upToDateTimeout = new UpToDateTimeout(1000, () => {
    sseManager.broadcast("up-to-date", { timestamp: new Date().toISOString() });
  });
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

        sseManager.sendToConnection(res, "initial", materializedViewToSparqlJson(materializedView));
        if (upToDateTimeout.isUpToDate()) {
          sseManager.sendToConnection(res, "up-to-date", { timestamp: new Date().toISOString() });
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
    deferredEvaluationTrigger: new EventEmitter(),
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

      sseManager.queueUpdate(true, bindingToSparqlJson(bindings).bindings[0]);
    } else {
      if (materializedView.has(key)) {
        const existingElement = materializedView.get(key)!;
        existingElement.count--;
        if (existingElement.count <= 0) {
          materializedView.delete(key);
        }

        sseManager.queueUpdate(false, bindingToSparqlJson(bindings).bindings[0]);
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

async function getSources(sourceTerms: any[]): Promise<QuerySourceIterator> {
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
  if (dynamicEndpoints.length > 0) {
    logger.info({ endpoints: dynamicEndpoints.length }, 'Starting dynamic endpoint SSE streams');
  }

  const sseCleanupFunctions: Array<() => void> = [];

  for (const descriptor of dynamicEndpoints) {
    try {
      const eventsUrl = descriptor.endpoint.replace(/\/$/, '') + '/events';
      logger.info({ endpoint: eventsUrl }, 'Subscribing to SSE stream');

      let response: Response;
      if (proxyUrl) {
        const sseRequest = {
          url: eventsUrl
        };
        response = await fetch(`${proxyUrl}/sse`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(sseRequest)
        });
      } else {
        response = await fetch(eventsUrl, {
          headers: {
            'Accept': 'text/event-stream'
          }
        });
      }

      if (!response.ok) {
        logger.error({ endpoint: eventsUrl, status: response.status }, 'Failed to connect to SSE stream');
        continue;
      }

      const reader = response.body?.getReader();
      if (!reader) {
        logger.error({ endpoint: eventsUrl }, 'No readable stream body');
        continue;
      }

      const decoder = new TextDecoder();
      let buffer = '';
      let isClosed = false;

      const processStream = async () => {
        try {
          while (!isClosed) {
            const { done, value } = await reader.read();
            if (done) {
              logger.info({ endpoint: eventsUrl }, 'SSE stream ended');
              break;
            }

            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split('\n');
            buffer = lines.pop() || '';

            let currentEvent: string | null = null;
            let currentData: string | null = null;

            for (const line of lines) {
              if (line.startsWith('event: ')) {
                currentEvent = line.slice(7).trim();
              } else if (line.startsWith('data: ')) {
                currentData = line.slice(6).trim();
              } else if (line === '' && currentEvent && currentData) {
                handleSSEEvent(descriptor, currentEvent, currentData);
                currentEvent = null;
                currentData = null;
              }
            }
          }
        } catch (e) {
          if (!isClosed) {
            logger.error({ endpoint: eventsUrl, error: e }, 'Error reading SSE stream');
          }
        }
      };

      const handleSSEEvent = (descriptor: { endpoint: string; variables: string[] }, event: string, data: string) => {
        try {
          if (event === 'initial' || event === 'processing' || event === 'up-to-date') {
            return;
          }

          const parsed = JSON.parse(data);

          if (event === 'update') {
            // Handle additions
            if (parsed.additions && Array.isArray(parsed.additions)) {
              for (const binding of parsed.additions) {
                const sources = collectSourcesFromBindingObject(binding, descriptor.variables);
                for (const source of sources) {
                  const prevCount = dynamicRefCounts.get(source) ?? 0;
                  dynamicRefCounts.set(source, prevCount + 1);
                  if (prevCount === 0 && !staticSources.has(source)) {
                    querySourceIterator.addSource(source);
                    logger.debug({ source, endpoint: descriptor.endpoint }, 'Dynamic source added via SSE');
                  }
                }
              }
            }

            // Handle deletions
            if (parsed.deletions && Array.isArray(parsed.deletions)) {
              for (const binding of parsed.deletions) {
                const sources = collectSourcesFromBindingObject(binding, descriptor.variables);
                for (const source of sources) {
                  const prevCount = dynamicRefCounts.get(source) ?? 0;
                  const nextCount = Math.max(0, prevCount - 1);
                  dynamicRefCounts.set(source, nextCount);
                  if (nextCount === 0 && !staticSources.has(source)) {
                    querySourceIterator.removeSource(source);
                    logger.debug({ source, endpoint: descriptor.endpoint }, 'Dynamic source removed via SSE');
                  }
                }
              }
            }
          }
        } catch (e) {
          logger.error({ endpoint: descriptor.endpoint, error: e }, 'Error handling SSE event');
        }
      };

      processStream();

      const cleanup = () => {
        isClosed = true;
        try {
          reader.cancel();
        } catch {}
      };
      sseCleanupFunctions.push(cleanup);

    } catch (e) {
      logger.error({ endpoint: descriptor.endpoint, error: e }, 'Error setting up SSE stream');
    }
  }

  const cleanup = () => {
    sseCleanupFunctions.forEach(fn => { try { fn(); } catch {} });
  };
  process.on('exit', cleanup);
  process.on('SIGINT', () => { cleanup(); process.exit(0); });
  process.on('SIGTERM', () => { cleanup(); process.exit(0); });

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
  let isShuttingDown = false;

  // Graceful shutdown handler
  async function gracefulShutdown(signal?: string) {
    if (isShuttingDown) {
      return;
    }
    isShuttingDown = true;

    if (signal) {
      logger.info({ signal }, 'Received shutdown signal');
    }

    try {
      await deregisterWithAggregator();
    } catch (error) {
      logger.error({ error }, 'Error during deregistration');
    }

    process.exit(signal === 'SIGTERM' || signal === 'SIGINT' ? 0 : 1);
  }

  // Handle various exit scenarios
  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
  process.on('SIGINT', () => gracefulShutdown('SIGINT'));
  process.on('uncaughtException', async (error) => {
    console.warn('Uncaught exception:', error);
    logger.error({ error }, 'Uncaught exception');
    await gracefulShutdown();
  });
  process.on('unhandledRejection', async (reason) => {
    logger.error({ reason }, 'Unhandled rejection');
    await gracefulShutdown();
  });

  main()
    .then(async () => {
      logger.error('Error: Incremunica client closed.');
      await gracefulShutdown();
    })
    .catch(async (error) => {
      logger.error({error}, 'Error starting Incremunica client');
      await gracefulShutdown();
    });
}
