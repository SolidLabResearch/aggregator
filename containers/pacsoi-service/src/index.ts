import { QuerySourceIterator } from '@incremunica/user-tools';
import { WeightDistribution } from "./weight-dist";
import { queryProcedures, querySources, queryWeights, queryQrs } from "./query";
import Fastify from "fastify";
import { Mutex } from "async-mutex";

async function main() {
  const weightSourceIterator = new QuerySourceIterator({ distinct: true });
  const procedureSourceIterator = new QuerySourceIterator({ distinct: true });
  const qrSourceIterator = new QuerySourceIterator({ distinct: true });

  const mutex = new Mutex();
  const dist = new WeightDistribution();

  const SOURCES = process.env.SOURCES;
  if (!SOURCES) {
    throw new Error("Environment variable SOURCES must be set");
  }

  querySources(
    SOURCES,
    weightSourceIterator,
    procedureSourceIterator,
    qrSourceIterator,
    dist,
    mutex
  );

  queryWeights(weightSourceIterator, dist, mutex);
  queryProcedures(procedureSourceIterator, dist, mutex);

  queryQrs(qrSourceIterator);

  // =========================
  // HTTP SERVER
  // =========================
  const app = Fastify();

  app.get("/dist", async (request, reply) => {
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