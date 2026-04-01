import { querySources, materializedViewToSparqlJson } from "./query.js";
import Fastify from "fastify";
import { Mutex } from "async-mutex";

async function main() {
  console.log("[BOOT] Starting application...");

  const mutex = new Mutex();
  const view: Map<string, { bindings: any; count: number }> = new Map();

  // =========================
  // ENV VALIDATION
  // =========================
  const SOURCES = process.env.SOURCES;
  if (!SOURCES) {
    console.error("[CONFIG] Missing SOURCES env variable");
    throw new Error("Environment variable SOURCES must be set");
  }
  const sources = SOURCES.split(",");
  console.log(`[CONFIG] Sources loaded (${sources.length}):`, sources);

  if (sources.length < 1) {
    console.error("[CONFIG] No sources provided");
    throw new Error("Expect at least one source");
  }

  const QUERY = process.env.QUERY;
  if (!QUERY) {
    console.error("[CONFIG] Missing QUERY env variable");
    throw new Error("Environment variable QUERY must be set");
  }
  console.log("[CONFIG] Query loaded");

  const SCHEMA = process.env.SCHEMA;
  if (!SCHEMA) {
    console.error("[CONFIG] Missing SCHEMA env variable");
    throw new Error("Environment variable SCHEMA must be set");
  }
  console.log("[CONFIG] Schema loaded");

  const CONTEXT = process.env.CONTEXT;
  if (!CONTEXT) {
    console.error("[CONFIG] Missing CONTEXT env variable");
    throw new Error("Environment variable CONTEXT must be set");
  }

  let context;
  try {
    context = JSON.parse(CONTEXT);
    console.log("[CONFIG] Context parsed successfully");
  } catch (err) {
    console.error("[CONFIG] Failed to parse CONTEXT:", err);
    throw err;
  }

  // =========================
  // QUERY SOURCES
  // =========================
  console.log("[QUERY] Starting querySources...");
  querySources(
    sources,
    QUERY,
    SCHEMA,
    context,
    view,
    mutex
  ).catch((err) => {
    console.error("[QUERY] querySources failed:", err);
  });

  // =========================
  // HTTP SERVER
  // =========================
  const app = Fastify({
    logger: false, // we use console.log manually
  });

  app.get("/", async (request, reply) => {
    console.log(`[HTTP] Incoming request from ${request.ip}`);

    return mutex.runExclusive(async () => {
      console.log("[HTTP] Acquired mutex, preparing response");

      try {
        const result = materializedViewToSparqlJson(view);
        console.log(`[HTTP] Returning result with ${view.size} entries`);

        reply.header("Content-Type", "application/sparql-results+json");
        return result;
      } catch (err) {
        console.error("[HTTP] Error while building response:", err);
        reply.status(500);
        return { error: "Internal server error" };
      }
    });
  });

  const port = 3000;
  await app.listen({ port, host: "0.0.0.0" });

  console.log(`[BOOT] Server listening on http://0.0.0.0:${port}`);
}

main().catch((err) => {
  console.error("[FATAL] Application crashed:", err);
  process.exit(1);
});