import { QuerySourceIterator } from '@incremunica/user-tools';
import { WeightDistribution } from "./weight-dist.js";
import { queryOxfordResponses, queryProcedures, querySources, queryWeights } from "./query.js";
import Fastify from "fastify";
import { Mutex } from "async-mutex";
import { OxfordScoreDistribution } from './oxford-dist.js';

async function main() {
  console.log('[MAIN] Starting application');

  const barProcedureSourceIterator = new QuerySourceIterator({ distinct: true });
  const kneeProcedureSourceIterator = new QuerySourceIterator({ distinct: true });

  const weightSourceIterator = new QuerySourceIterator({ distinct: true });
  const oxfordSourceIterator = new QuerySourceIterator({ distinct: true });

  const mutex = new Mutex();
  const weightDist = new WeightDistribution();
  const oxfordDist = new OxfordScoreDistribution();

  const SOURCES = process.env.SOURCES;
  if (!SOURCES) {
    throw new Error("Environment variable SOURCES must be set");
  }

  const BAR_PROCEDURE_SLICE = process.env.BAR_PROCEDURE_SLICE;
  if (!BAR_PROCEDURE_SLICE) {
    throw new Error("Environment variable BAR_PROCEDURE_SLICE must be set");
  }

  const KNEE_PROCEDURE_SLICE = process.env.KNEE_PROCEDURE_SLICE;
  if (!KNEE_PROCEDURE_SLICE) {
    throw new Error("Environment variable KNEE_PROCEDURE_SLICE must be set");
  }

  const WEIGHT_SLICE = process.env.WEIGHT_SLICE;
  if (!WEIGHT_SLICE) {
    throw new Error("Environment variable WEIGHT_SLICE must be set");
  }

  const OXFORD_SLICE = process.env.OXFORD_SLICE;
  if (!OXFORD_SLICE) {
    throw new Error("Environment variable OXFORD_SLICE must be set");
  }

  querySources(
    SOURCES,
    BAR_PROCEDURE_SLICE.startsWith("/") ? BAR_PROCEDURE_SLICE.slice(1) : BAR_PROCEDURE_SLICE,
    barProcedureSourceIterator,
    KNEE_PROCEDURE_SLICE.startsWith("/") ? KNEE_PROCEDURE_SLICE.slice(1) : KNEE_PROCEDURE_SLICE,
    kneeProcedureSourceIterator,
    WEIGHT_SLICE.startsWith("/") ? WEIGHT_SLICE.slice(1) : WEIGHT_SLICE,
    weightSourceIterator,
    OXFORD_SLICE.startsWith("/") ? OXFORD_SLICE.slice(1) : OXFORD_SLICE,
    oxfordSourceIterator,
  );

  queryProcedures(barProcedureSourceIterator, weightDist, mutex);
  queryProcedures(kneeProcedureSourceIterator, oxfordDist, mutex);
  queryWeights(weightSourceIterator, weightDist, mutex);
  queryOxfordResponses(oxfordSourceIterator, oxfordDist, mutex);

  // =========================
  // HTTP SERVER
  // =========================
  const app = Fastify();

  app.get("/w-dist", async (request, reply) => {
    const csv = await mutex.runExclusive(() => weightDist.toCSV());
    
    reply
      .header("Content-Type", "text/csv")
      .header("Content-Disposition", "attachment; filename=dist.csv")
      .send(csv);
  });

  app.get("/o-dist", async (request, reply) => {
    const csv = await mutex.runExclusive(() => oxfordDist.toCSV());
    
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