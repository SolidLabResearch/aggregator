import { WeightDistribution } from "./weight-dist.js";
import { queryProcedures, queryWeights } from "./query.js";
import * as Schemas from './schemas.js';
import Fastify from "fastify";
import { Mutex } from "async-mutex";

async function main() {
  console.log('[MAIN] Starting application');

  const mutex = new Mutex();
  const dist = new WeightDistribution();

  const SOURCES = process.env.SOURCES;
  if (!SOURCES) {
    throw new Error("Environment variable SOURCES must be set");
  }

  const sources = SOURCES.split(",");
  console.log(`[CONFIG] Sources loaded (${sources.length}):`, sources);

  if (sources.length < 1) {
    console.error("[CONFIG] No sources provided");
    throw new Error("Expect at least one source");
  }

  const procedureSources: any[] = [];
  const weightSources: any[] = [];

  sources.forEach((endpoint) => {
    const procedureSource = {
      value: endpoint + Schemas.PROCEDURE_SLICE,
      type: "graphql",
      context: {
        schema: Schemas.PROCEDURE_SLICE_SCHEMA,
        context: Schemas.PROCEDURE_SLICE_CONTEXT,
      },
    };
    procedureSources.push(procedureSource);
    console.log(`[CONFIG] Added procedure source: ${procedureSource.value}`);

    const weightSource = {
      value: endpoint + Schemas.WEIGHT_SLICE,
      type: "graphql",
      context: {
        schema: Schemas.WEIGHT_SLICE_SCHEMA,
        context: Schemas.WEIGHT_SLICE_CONTEXT,
      },
    };

    weightSources.push(weightSource);
    console.log(`[CONFIG] Added weight source: ${weightSource.value}`);
  });

  console.log('[MAIN] Starting streaming queries');
  queryProcedures(procedureSources, dist, mutex);
  queryWeights(weightSources, dist, mutex);

  // =========================
  // HTTP SERVER
  // =========================
  const app = Fastify();

  app.get("/w-dist", async (request, reply) => {
    console.log('[HTTP] /w-dist requested');
    const csv = await mutex.runExclusive(() => dist.toCSV());

    console.log('[HTTP] /w-dist response generated, sending CSV');
    reply
      .header("Content-Type", "text/csv")
      .header("Content-Disposition", "attachment; filename=dist.csv")
      .send(csv);
  });

  const port = 3000;
  await app.listen({ port, host: "0.0.0.0" });
  console.log(`[MAIN] HTTP server listening on 0.0.0.0:${port}`);
}

main().catch((err) => {
  console.error('[MAIN] Error:', err);
  process.exit(1);
});