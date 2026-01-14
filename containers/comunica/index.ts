import { QueryEngine as GraphqlQueryEngine } from "@comunica-graphql/query-sparql-graphql";
import { QueryEngine as SparqlQueryEngine } from "@comunica/query-sparql";
import http from 'http';

const proxyUrl = process.env.http_proxy || process.env.HTTP_PROXY;

export async function fetchProxy(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  // If no proxy is configured, use native fetch
  if (!proxyUrl) {
    return fetch(input, init);
  }

  // Resolve the URL for logging/Host purposes
  const targetUrl =
    typeof input === "string"
      ? new URL(input)
      : input instanceof URL
      ? input
      : new URL(input.url);

  // Determine method
  const method = init?.method || (input instanceof Request ? input.method : "GET");

  // Determine body
  let bodyString: string | undefined = undefined;

  if (init?.body) {
    // Body may be Blob, BufferSource, FormData, string, etc.
    bodyString = typeof init.body === "string" ? init.body : await convertBodyToString(init.body);
  } else if (input instanceof Request && input.body) {
    bodyString = await input.clone().text();
  }

  // Build JSON payload for proxy /fetch endpoint
  const payload = {
    target_url: targetUrl.toString(),
    target_method: method,
    target_body: bodyString || ""
  };

  // Do NOT forward user-level headers; the proxy will manage UMA and Host
  // But you can forward some user headers safely if needed.

  return fetch(`${proxyUrl}/fetch`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  });
}

async function convertBodyToString(body: BodyInit): Promise<string> {
  if (typeof body === "string") return body;

  if (body instanceof Blob) {
    return await body.text();
  }

  if (body instanceof ArrayBuffer) {
    return new TextDecoder().decode(body);
  }

  if (ArrayBuffer.isView(body)) {
    return new TextDecoder().decode(body.buffer);
  }

  if (body instanceof URLSearchParams) {
    return body.toString();
  }

  if (body instanceof FormData) {
    // JSONify FormData structure (no file support)
    const obj: Record<string, string> = {};
    body.forEach((value, key) => {
      obj[key] = String(value);
    });
    return JSON.stringify(obj);
  }

  // Last resort
  return await new Response(body).text();
}

async function main() {
  // Load from environment
  const query = process.env.QUERY;
  if (!query) {
    throw new Error("Environment variable QUERY is required");
  }

  const sourcesRaw = process.env.SOURCES;
  if (!sourcesRaw) {
    throw new Error("Environment variable SOURCES is required");
  }

  const sourceURLs = sourcesRaw.split(",").map(s => s.trim());

  const contextRaw = process.env.CONTEXT;
  const schema = process.env.SCHEMA;

  let context: Record<string, string> | undefined;
  if (contextRaw) {
    try {
      context = JSON.parse(contextRaw);
    } catch (err) {
      throw new Error(`Failed to parse CONTEXT: ${err}`);
    }
  }

  const useGraphQL = !!(schema && context);

  let sources: Array<Source | string>;
  if (useGraphQL) {
    sources = sourceURLs.map(url => ({
      type: "graphql" as const,
      value: url,
      context: {
        schema: schema!,
        context: context!
      }
    }));
    console.log("Using GraphQL engine with schema and context");
  } else {
    sources = sourceURLs;
    console.log("Using SPARQL engine with RDF sources");
  }

  console.log("QUERY:", query);
  console.log("SOURCES:", sourceURLs);
  if (context) console.log("CONTEXT:", context);
  if (schema) console.log("SCHEMA:", schema);

  const graphqlEngine = useGraphQL ? new GraphqlQueryEngine() : null;
  const sparqlEngine = new SparqlQueryEngine();

  const server = http.createServer((req, res) => {
    (async () => {
      try {
        console.log(`Received request: ${req.method} ${req.url}`);

        if (req.method === "GET" && req.url === "/health") {
          res.writeHead(200, { "Content-Type": "text/plain" });
          res.end("OK");
          return;
        }

        if (req.method === "GET" && req.url === "/") {
          let result;

          if (useGraphQL && graphqlEngine) {
            try {
              result = await graphqlEngine.query(query, {
                sources: sources as any,
                fetch: fetchProxy,
                lenient: true
              });
            } catch (e: any) {
              if (e.message && (e.message.includes("variable predicate") || e.message.includes("does not exist in the schema"))) {
                console.log("Fallback to Generic SPARQL Engine:", e.message);
                result = await sparqlEngine.query(query, {
                  sources: sourceURLs as any,
                  fetch: fetchProxy,
                  lenient: true
                });
              } else {
                throw e;
              }
            }
          } else {
            result = await sparqlEngine.query(query, {
              sources: sources as any,
              fetch: fetchProxy,
              lenient: true
            });
          }

          let mediaType: string;
          switch (result.resultType) {
            case "bindings":
            case "boolean":
              mediaType = "application/sparql-results+json";
              break;
            case "quads":
              mediaType = "text/turtle";
              break;
            default:
              res.writeHead(400, { "Content-Type": "text/plain" });
              res.end("Unsupported query result type.");
              return;
          }

          // Only write headers after result is validated
          res.writeHead(200, { "Content-Type": mediaType });

          const { data } = await sparqlEngine.resultToString(result, mediaType);

          // Handle stream errors
          data.on("error", (err: any) => {
            console.error("Stream error:", err);
            if (!res.headersSent) {
              res.writeHead(500, { "Content-Type": "text/plain" });
            }
            res.end("Internal server error");
          });

          data.pipe(res);
        } else {
          res.writeHead(404, { "Content-Type": "text/plain" });
          res.end("Not found");
        }
      } catch (err) {
        console.error("Server error:", err);
        if (!res.headersSent) {
          res.writeHead(500, { "Content-Type": "text/plain" });
        }
        res.end("Internal server error");
      }
    })();
  });

  server.listen(8080, '0.0.0.0', () => {
    console.log("SPARQL SELECT result server running at http://0.0.0.0:8080/");
  });
}

interface Source {
  type: 'graphql',
  value: string,
  context?: {
    schema: string,
    context: Record<string, string>,
  },
}

main();
