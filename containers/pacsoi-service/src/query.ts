import { QueryEngine } from "@incremunica/query-sparql-incremental";
import { isAddition, QuerySourceIterator } from '@incremunica/user-tools';
import * as Schemas from "./schemas.js";
import { WeightDistribution } from "./weight-dist.js";
import { Mutex } from "async-mutex";

export async function querySources(
  endpoint: string, 
  weightSlice: string,
  weightSourceIterator: QuerySourceIterator,
  procedureSlice: string,
  procedureSourceIterator: QuerySourceIterator,
  dist: WeightDistribution,
  mutex: Mutex
) {
  const engine = new QueryEngine();
  console.log('[querySources] Starting sources query');

  const bindingsStream = await engine.queryBindings(Schemas.HCP_QUERY, {
    sources: [
      {
        value: endpoint,
        type: "graphql",
        context: {
          schema: Schemas.HCP_SLICE_SCHEMA,
          context: Schemas.HCP_SLICE_CONTEXT
        }
      }
    ],
    fetch: umaProxyFetch
  });

  bindingsStream.on('data', async (b) => {
    if (b.has('pod')) {
      const procedureSource = {
        value: b.get('pod').value + "/slices/" + procedureSlice + "/query",
        type: "graphql",
        context: {
          schema: Schemas.BAR_PROCEDURE_SLICE_SCHEMA,
          context: Schemas.BAR_PROCEDURE_SLICE_CONTEXT
        }
      }

      const weightSource = {
        value: b.get('pod').value + "/slices/" + weightSlice + "/query",
        type: "graphql",
        context: {
          schema: Schemas.WEIGHT_SLICE_SCHEMA,
          context: Schemas.WEIGHT_SLICE_CONTEXT
        }
      }

      if (isAddition(b)) {
        console.log('[querySources] Received addition:', b.toString());
        procedureSourceIterator.addSource(procedureSource);
        weightSourceIterator.addSource(weightSource);
      } else {
        console.log('[querySources] Received deletion:', b.toString());
        procedureSourceIterator.removeSource(procedureSource);
        weightSourceIterator.removeSource(weightSource);
        // await mutex.runExclusive(() => dist.removePatient(b.get('id').value));
      }
    }
  });

  bindingsStream.on('end', () => {
    console.log('[querySources] Source stream ended');
  });

  bindingsStream.on('error', (err) => {
    console.log('[querySources] Source stream error: ', err)
  });
}

export async function queryWeights(sourceIterater: QuerySourceIterator, dist: WeightDistribution, mutex: Mutex) {
  const engine = new QueryEngine();
  console.log('[queryWeights] Starting weight query');

  const bindingsStream = await engine.queryBindings(Schemas.WEIGHT_QUERY, {
    sources: [{
      value: sourceIterater,
      type: "stream-graphql"
    } as any],
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
        await mutex.runExclusive(() => dist.addWeightObservation(patientID, value, timestamp));
      }
    }
  });

  bindingsStream.on('end', () => {
    console.log('[queryWeights] Weight stream ended');
  });

  bindingsStream.on('error', (err) => {
    console.log('[queryWeights] Weight stream error: ', err)
  });
}

export async function queryProcedures(sourceIterater: QuerySourceIterator, dist: WeightDistribution, mutex: Mutex) {
  const engine = new QueryEngine();
  console.log('[queryProcedures] Starting procedure query');

  const bindingsStream = await engine.queryBindings(Schemas.BAR_PROCEDURE_QUERY, {
    sources: [{
      value: sourceIterater,
      type: "stream-graphql"
     } as any],
    fetch: umaProxyFetch
  });

  bindingsStream.on('data', async (b) => {
    if (isAddition(b)) {
      console.log('[queryProcedures] Received addition:', b.toString());
      if (b.has('timestamp') && b.has('patient')) {
        const timestamp = new Date(b.get('timestamp').value);
        const patientID = b.get('patient').value;

        console.log(`[queryProcedures] Adding procedure for patient ${patientID}: timestamp=${timestamp.toISOString()}`);
        await mutex.runExclusive(() => dist.addPatientProcedure(patientID, timestamp));
      }
    }
  });
}

async function umaProxyFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  let target = input.toString();
  const originalUrl = target;

  console.log(`[FETCH] Requesting: ${originalUrl}`);

  const BASE_DELAY_MS = 1000;
  const MAX_DELAY_MS = 300000;
  const BACKOFF_FACTOR = 2;

  for (let attempt = 0; ; attempt++) {
    const delay = Math.min(BASE_DELAY_MS * BACKOFF_FACTOR ** attempt, MAX_DELAY_MS);

    try {
      let response: Response;

      if (!process.env.HTTP_PROXY && !process.env.http_proxy) {
        console.log("[FETCH] No proxy configured, direct request");
        response = await fetch(input, init);
      } else {
        console.log("[FETCH] Using proxy");
        target = (process.env.HTTP_PROXY || process.env.http_proxy) + "/fetch";

        const bodyHeaders: Record<string, string> = {};
        if (init?.headers) {
          if (init.headers instanceof Headers) {
            init.headers.forEach((v, k) => (bodyHeaders[k] = v));
          } else if (Array.isArray(init.headers)) {
            init.headers.forEach(([k, v]) => (bodyHeaders[k] = v));
          } else {
            Object.assign(bodyHeaders, init.headers);
          }
        }

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
          method: init?.method || "GET",
          headers: bodyHeaders,
          body: init?.body ? init.body.toString() : "",
        };

        console.log("[FETCH] Proxy request payload prepared");

        response = await fetch(target, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(fetchRequest),
        });

        console.log(`[FETCH] Proxy response received (status: ${response.status})`);

        Object.defineProperty(response, "url", {
          value: originalUrl,
          writable: false,
          enumerable: true,
          configurable: false,
        });
      }

      if (!response.ok) {
        throw new Error(`Response not ok: ${response.status} ${response.statusText}`);
      }

      if (attempt > 0) {
        console.log(`[FETCH] Succeeded on attempt ${attempt + 1}`);
      }

      return response;

    } catch (error) {
      console.warn(`[FETCH] Attempt ${attempt + 1} failed: ${(error as Error).message}. Retrying in ${delay}ms...`);
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }
}