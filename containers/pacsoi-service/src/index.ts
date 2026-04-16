import { QuerySourceIterator } from '@incremunica/user-tools';
import { WeightDistribution } from "./weight-dist.js";
import { queryProcedures, querySources, queryWeights } from "./query.js";
import Fastify from "fastify";
import { Mutex } from "async-mutex";

async function main() {
  console.log('[MAIN] Starting application');

  const weightSourceIterator = new QuerySourceIterator({ distinct: true });
  const procedureSourceIterator = new QuerySourceIterator({ distinct: true });

  const mutex = new Mutex();
  const dist = new WeightDistribution();

  const SOURCES = process.env.SOURCES;
  if (!SOURCES) {
    throw new Error("Environment variable SOURCES must be set");
  }

  const WEIGHT_SLICE = process.env.WEIGHT_SLICE;
  if (!WEIGHT_SLICE) {
    throw new Error("Environment variable WEIGHT_SLICE must be set");
  }

  const PROCEDURE_SLICE = process.env.PROCEDURE_SLICE;
  if (!PROCEDURE_SLICE) {
    throw new Error("Environment variable PROCEDURE_SLICE must be set");
  }

  querySources(
    SOURCES,
    WEIGHT_SLICE.startsWith("/") ? WEIGHT_SLICE.slice(1) : WEIGHT_SLICE,
    weightSourceIterator,
    PROCEDURE_SLICE.startsWith("/") ? PROCEDURE_SLICE.slice(1) : PROCEDURE_SLICE,
    procedureSourceIterator,
    dist,
    mutex
  );

  queryWeights(weightSourceIterator, dist, mutex);
  queryProcedures(procedureSourceIterator, dist, mutex);

  // =========================
  // HTTP SERVER
  // =========================
  const app = Fastify();

  app.get("/w-dist", async (request, reply) => {
    const csv = await mutex.runExclusive(() => dist.toCSV());
    
    reply
      .header("Content-Type", "text/csv")
      .header("Content-Disposition", "attachment; filename=dist.csv")
      .send(csv);
  });

  const port = 3000;
  await app.listen({ port, host: "0.0.0.0" });
}

main().catch((err) => {
  console.log(err);
  process.exit(1);
});