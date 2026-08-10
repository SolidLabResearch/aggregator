import { QueryEngine } from "@incremunica/query-sparql-incremental";
import { isAddition } from '@incremunica/user-tools';
import { Mutex } from "async-mutex";

export async function querySources(
  endpoints: string[],
  query: string,
  schema: string,
  context: Record<string, string>,
  view: Map<string,{bindings: any, count: number}>,
  mutex: Mutex
) {
  console.log("[QUERY] Initializing QueryEngine...");
  const engine = new QueryEngine();

  console.log(`[QUERY] Preparing ${endpoints.length} endpoints`);
  const sources = endpoints.map(endpoint => {
    console.log(`[QUERY] Adding source: ${endpoint}`);
    return {
      value: endpoint,
      type: "graphql",
      context: {
        schema: schema,
        context: context
      }
    }
  });

  console.log("[QUERY] Executing query...");
  const bindingsStream = await engine.queryBindings(query, {
    sources: <any>sources,
    fetch: umaProxyFetch
  });

  console.log("[STREAM] Query stream started");

  bindingsStream.on('data', async (b) => {
    const key = b.toString();
    const addition = isAddition(b);

    console.log(`[STREAM] ${addition ? "ADD" : "REMOVE"} event: ${key}`);

    if (addition) {
      if (view.has(key)) {
        await mutex.runExclusive(() => {
          const entry = view.get(key)!;
          entry.count++;
          console.log(`[VIEW] Incremented count (${entry.count}) for key`);
        });
      } else {
        await mutex.runExclusive(() => {
          view.set(key, { bindings: b, count: 1 });
          console.log("[VIEW] Added new entry with count=1");
        });
      }
    } else {
      await mutex.runExclusive(() => {
        if (view.has(key)) {
          const existingElement = view.get(key)!;
          existingElement.count--;
          console.log(`[VIEW] Decremented count (${existingElement.count})`);

          if (existingElement.count <= 0) {
            view.delete(key);
            console.log("[VIEW] Entry removed (count <= 0)");
          }
        } else {
          console.error("[ERROR] Removal received for non-existing key:", key);
        }
      });
    }
  });

  bindingsStream.on('end', () => {
    console.log("[STREAM] Query stream ended");
  });

  bindingsStream.on('error', (err) => {
    console.error('[STREAM] Error during query execution:', err);
  });
}

export function materializedViewToSparqlJson(view: Map<string,{bindings: any, count: number}>) {
  console.log(`[SERIALIZE] Converting materialized view (${view.size} entries)`);

  const variablesSet: Set<string> = new Set();
  const results: {[variableName: string]: {type: string, value: string, datatype?: string, "xml:lang"?: string }}[] = [];

  for (const element of view.values()) {
    for (const variable of element.bindings.keys()) {
      variablesSet.add(variable.value);
    }

    let result: {[variableName: string]: {type: string, value: string, datatype?: string, "xml:lang"?: string }} = {};

    for (const [variable, value] of element.bindings) {
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

    for (let i = 0; i < element.count; i++) {
      results.push(result);
    }
  }

  console.log(`[SERIALIZE] Generated ${results.length} result rows`);

  return {
    head: { vars: [...variablesSet.keys()] },
    results: { bindings: results },
  };
}

async function umaProxyFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  let target = input.toString();
  const originalUrl = target;

  console.log(`[FETCH] Requesting: ${originalUrl}`);

  const egressUmaUrl = process.env.EGRESS_UMA_URL?.replace(/\/+$/, "");
  if (!egressUmaUrl) {
    console.log("[FETCH] No UMA egress configured, direct request");
    return fetch(input, init);
  }
  console.log("[FETCH] Using UMA egress");
  target = egressUmaUrl + "/fetch";

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
