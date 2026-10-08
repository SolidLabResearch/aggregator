import { QuerySourceIterator } from '@incremunica/user-tools';
import { WeightDistribution } from "./weight-dist.js";
import { queryBariatricResponses, queryProcedures, querySources, queryWeights } from "./query.js";
import Fastify from "fastify";
import { Mutex } from "async-mutex";
import { BariatricScoreDistribution } from './bariatric-dist.js';
import * as Schemas from "./schemas.js";

/**
 * Application entry point.
 *
 * The service maintains two independent in-memory projections (weight and
 * bariatric questionnaire scores). Incremental SPARQL streams update those
 * projections while Fastify exposes consistent CSV snapshots. Separate mutexes
 * ensure a request cannot read a projection halfway through an update.
 */
async function main() {
  console.log('[MAIN] Starting application');

  const barProcedureSourceIterator = new QuerySourceIterator({ distinct: true });

  const weightSourceIterator = new QuerySourceIterator({ distinct: true });
  const questionnaireSourceIterator = new QuerySourceIterator({ distinct: true });

  const weightMutex = new Mutex();
  const weightDist = new WeightDistribution();
  const bariatricMutex = new Mutex();
  const bariatricDist = new BariatricScoreDistribution();

  const ACTIVE_PATIENTS_URL = process.env.ACTIVE_PATIENTS_URL;
  if (!ACTIVE_PATIENTS_URL) {
    throw new Error("Environment variable ACTIVE_PATIENTS_URL must be set");
  }

  const POD_BASE_URL = process.env.POD_BASE_URL;
  if (!POD_BASE_URL) {
    throw new Error("Environment variable POD_BASE_URL must be set");
  }

  const ACTIVE_PATIENTS_POLL_INTERVAL_MS = Number(
    process.env.ACTIVE_PATIENTS_POLL_INTERVAL_MS ?? "60000",
  );
  if (!Number.isFinite(ACTIVE_PATIENTS_POLL_INTERVAL_MS) || ACTIVE_PATIENTS_POLL_INTERVAL_MS <= 0) {
    throw new Error("Environment variable ACTIVE_PATIENTS_POLL_INTERVAL_MS must be a positive number");
  }

  const PATIENT_SLICE = process.env.PATIENT_SLICE;
  if (!PATIENT_SLICE) {
    throw new Error("Environment variable PATIENT_SLICE must be set");
  }

  const BAR_PROCEDURE_SLICE = process.env.BAR_PROCEDURE_SLICE;
  if (!BAR_PROCEDURE_SLICE) {
    throw new Error("Environment variable BAR_PROCEDURE_SLICE must be set");
  }

  const WEIGHT_SLICE = process.env.WEIGHT_SLICE;
  if (!WEIGHT_SLICE) {
    throw new Error("Environment variable WEIGHT_SLICE must be set");
  }

  const questionnaireSliceDefinitions = [
    ["QUESTIONNAIRE_PREOP_SLICE", Schemas.QUESTIONNAIRE_PREOP_SLICE_SCHEMA],
    ["QUESTIONNAIRE_POSTOP6W_SLICE", Schemas.QUESTIONNAIRE_POSTOP6W_SLICE_SCHEMA],
    ["QUESTIONNAIRE_POSTOP3M_SLICE", Schemas.QUESTIONNAIRE_POSTOP3M_SLICE_SCHEMA],
    ["QUESTIONNAIRE_POSTOP6M_SLICE", Schemas.QUESTIONNAIRE_POSTOP6M_SLICE_SCHEMA],
    ["QUESTIONNAIRE_POSTOP1Y_SLICE", Schemas.QUESTIONNAIRE_POSTOP1Y_SLICE_SCHEMA],
  ] as const;
  const questionnaireSlices = questionnaireSliceDefinitions.map(([name, schema]) => {
    const value = process.env[name];
    if (!value) throw new Error(`Environment variable ${name} must be set`);
    return { slice: value.startsWith("/") ? value.slice(1) : value, schema };
  });

  void querySources(
    ACTIVE_PATIENTS_URL,
    POD_BASE_URL,
    PATIENT_SLICE,
    BAR_PROCEDURE_SLICE.startsWith("/") ? BAR_PROCEDURE_SLICE.slice(1) : BAR_PROCEDURE_SLICE,
    barProcedureSourceIterator,
    WEIGHT_SLICE.startsWith("/") ? WEIGHT_SLICE.slice(1) : WEIGHT_SLICE,
    weightSourceIterator,
    questionnaireSlices,
    questionnaireSourceIterator,
    weightMutex,
    weightDist,
    bariatricMutex,
    bariatricDist,
    ACTIVE_PATIENTS_POLL_INTERVAL_MS,
  );

  queryProcedures(barProcedureSourceIterator, weightDist, weightMutex);
  queryWeights(weightSourceIterator, weightDist, weightMutex);
  queryBariatricResponses(questionnaireSourceIterator, bariatricDist, bariatricMutex);

  // The incremental queries attach long-lived stream handlers; the source
  // poller runs in the background. Both deliberately live with this process.
  const app = Fastify();

  app.get("/w-dist", async (request, reply) => {
    const csv = await weightMutex.runExclusive(() => weightDist.toCSV());

    reply
      .header("Content-Type", "text/csv")
      .header("Content-Disposition", "attachment; filename=dist.csv")
      .send(csv);
  });

  app.get("/b-dist", async (request, reply) => {
    const csv = await bariatricMutex.runExclusive(() => bariatricDist.toCSV());

    reply
      .header("Content-Type", "text/csv")
      .header("Content-Disposition", "attachment; filename=bariatric-scores.csv")
      .send(csv);
  });

  const port = 3000;
  await app.listen({ port, host: "0.0.0.0" });
}

main().catch((err) => {
  console.log(err);
  process.exit(1);
});
