import { QueryEngine } from "@comunica-graphql/query-sparql-graphql";
import http from 'http';
import { url } from "inspector";

const proxyUrl = process.env.http_proxy || process.env.HTTP_PROXY;
if (proxyUrl === undefined) {
  throw new Error('Environment variable HTTP_PROXY is not set. Please provide the URL of the proxy server.');
}

export async function fetchProxy(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
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
    const text = await input.clone().text();
    bodyString = text;
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
  const text = await new Response(body).text();
  return text;
}

async function main() {
  // Load from environment
  const query = process.env.QUERY;
  if (!query) {
    throw new Error("Environment variable QUERY is required");
  }

  const sourceURL = process.env.SOURCE;
  if (!sourceURL) {
    throw new Error("Environment variable SOURCE is required");
  }

  const contextRaw = process.env.CONTEXT;
  if (!contextRaw) {
    throw new Error("Environment variable CONTEXT is required");
  }

  let context: Record<string, string>;
  try {
    context = JSON.parse(contextRaw);
  } catch (err) {
    throw new Error(`Failed to parse CONTEXT: ${err}`);
  }

  const schema = process.env.SCHEMA;
  if (!schema) {
    throw new Error("Environment variable SCHEMA is required");
  }

  const source: Source = {
    type: "graphql",
    value: sourceURL,
    context: {
      schema: schema,
      context: context
    }
  };

  // ✅ Now you have:
  console.log("QUERY:", query);
  console.log("SOURCE:", sourceURL);
  console.log("CONTEXT:", context);
  console.log("SCHEMA:", schema);

  const queryEngine = new QueryEngine();

  const server = http.createServer((req, res) => {
    (async () => {
      try {
        console.log(`Received request: ${req.method} ${req.url}`);

        if (req.method === "GET" && req.url === "/") {
          const result = await queryEngine.query(query, { 
            sources: [source],
            fetch: fetchProxy
          });

          if (result.resultType !== "bindings") {
            res.writeHead(400, { "Content-Type": "text/plain" });
            res.end("Only SELECT queries with bindings are supported.");
            return;
          }

          // Only write headers after result is validated
          res.writeHead(200, { "Content-Type": "application/sparql-results+json" });

          const { data } = await queryEngine.resultToString(result, "application/sparql-results+json");

          // Handle stream errors
          data.on("error", (err) => {
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