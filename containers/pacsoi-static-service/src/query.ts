import { QueryEngine } from "@incremunica/query-sparql-incremental";
import { isAddition, QuerySourceIterator } from '@incremunica/user-tools';
import * as Schemas from "./schemas.js";
import { WeightDistribution } from "./weight-dist.js";
import { Mutex } from "async-mutex";

export async function queryWeights(
  sources: any[],
  dist: WeightDistribution,
  mutex: Mutex
) {
  const engine = new QueryEngine();
  console.log('[queryWeights] Starting weight query');

  const bindingsStream = await engine.queryBindings(Schemas.WEIGHT_QUERY, {
    sources: <any>sources,
    fetch: umaProxyFetch
  });

  bindingsStream.on('data', async (b) => {
    if (isAddition(b)) {
      console.log('[queryWeights] Received addition:', b.toString());
      if (b.has('value') && b.has('timestamp') && b.has('patient')) {
        const value = parseFloat(b.get('value').value);
        const timestamp = new Date(b.get('timestamp').value);
        const patientID = b.get('patient').value;

        console.log(`[queryWeights] Adding weight observation for patient ${patientID}: value=${value}, timestamp=${timestamp.toISOString()}`);
        await mutex.runExclusive(async () => {
          dist.addWeightObservation(patientID, value, timestamp);
        });
      }
    }
  });

  bindingsStream.on('end', () => {
    console.log('[queryWeights] Weight stream ended');
  });
}

export async function queryProcedures(
  sources: any[],
  dist: WeightDistribution,
  mutex: Mutex
) {
  const engine = new QueryEngine();
  console.log('[queryProcedures] Starting procedure query');

  const bindingsStream = await engine.queryBindings(Schemas.PROCEDURE_QUERY, {
    sources: <any>sources,
    fetch: umaProxyFetch
  });

  bindingsStream.on('data', async (b) => {
    if (isAddition(b)) {
      console.log('[queryProcedures] Received addition:', b.toString());
      if (b.has('timestamp') && b.has('patient')) {
        const timestamp = new Date(b.get('timestamp').value);
        const patientID = b.get('patient').value;

        console.log(`[queryProcedures] Adding procedure for patient ${patientID}: timestamp=${timestamp.toISOString()}`);
        await mutex.runExclusive(async () => {
          dist.addPatientProcedure(patientID, timestamp);
        });
      }
    }
  });

  bindingsStream.on('end', () => {
    console.log('[queryProcedures] Procedure stream ended');
  });
}

export async function queryQrs(sourceIterater: QuerySourceIterator) {
  console.log('[queryQrs] Function called, not yet implemented');
}

async function umaProxyFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  let target = input.toString();
  const originalUrl = target;

  console.log(`[FETCH] Requesting: ${originalUrl}`);

  if (!process.env.HTTP_PROXY && !process.env.http_proxy) {
    console.log("[FETCH] No proxy configured, direct request");
    return fetch(input, init);
  }
  console.log("[FETCH] Using proxy");
  target = (process.env.HTTP_PROXY || process.env.http_proxy) + "/fetch";

  // Prepare headers for the proxy payload
  const bodyHeaders: Record<string, string> = {};
  if (init?.headers) {
    // Copy all headers from init
    if (init.headers instanceof Headers) {
      init.headers.forEach((v, k) => (bodyHeaders[k] = v));
    } else if (Array.isArray(init.headers)) {
      init.headers.forEach(([k, v]) => (bodyHeaders[k] = v));
    } else {
      Object.assign(bodyHeaders, init.headers);
    }
  }

  // If SSE, ensure necessary headers
  const acceptHeader = init?.headers instanceof Headers
    ? init.headers.get("Accept")
    : typeof init?.headers === "object"
      ? (init.headers as Record<string, string>)["Accept"]
      : undefined;

  if (acceptHeader === "text/event-stream") {
    console.log("[FETCH] SSE detected, adding streaming headers to payload");
    bodyHeaders["Accept"] = "text/event-stream";
    bodyHeaders["Cache-Control"] = "no-cache";
    bodyHeaders["Connection"] = "keep-alive";
  }

  const fetchRequest = {
    url: originalUrl,
    method: init?.method || 'GET',
    headers: bodyHeaders,
    body: init?.body ? init.body.toString() : ''
  };

  console.log("[FETCH] Proxy request payload prepared");

  const response = await fetch(target, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(fetchRequest)
  });

  console.log(`[FETCH] Proxy response received (status: ${response.status})`);

  Object.defineProperty(response, 'url', {
    value: originalUrl,
    writable: false,
    enumerable: true,
    configurable: false
  });

  return response;
}