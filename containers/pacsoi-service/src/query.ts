import { QueryEngine } from "@incremunica/query-sparql-incremental";
import { isAddition, QuerySourceIterator } from '@incremunica/user-tools';
import * as Schemas from "./schemas.js";
import { WeightDistribution } from "./weight-dist.js";
import { Mutex } from "async-mutex";
import { OxfordScoreDistribution } from "./oxford-dist.js";

/**
 * Watches the doctor's HCP slice and turns every discovered patient pod into
 * five live GraphQL sources. Additions and removals are propagated to the
 * corresponding QuerySourceIterator, so downstream incremental queries track
 * the current set of pods without restarting the service. When the HCP relation
 * is deleted, the canonical patient binding is also removed from both in-memory
 * projections.
 *
 * Slice names passed here must not start with a slash (normalised by index.ts),
 * except patientSlice, which is accepted in either form for compatibility.
 */
export async function querySources(
  endpoint: string,
  patientSlice: string,
  patientSourceIterator: QuerySourceIterator,
  barProcedureSlice: string,
  barProcedureSourceIterator: QuerySourceIterator,
  kneeProcedureSlice: string,
  kneeProcedureSourceIterator: QuerySourceIterator,
  weightSlice: string,
  weightSourceIterator: QuerySourceIterator,
  oxfordSlice: string,
  oxfordSourceIterator: QuerySourceIterator,
  wMutex: Mutex,
  wDist: WeightDistribution,
  oMutex: Mutex,
  oDist: OxfordScoreDistribution,
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
      const normalizedPatientSlice = patientSlice.startsWith("/")
        ? patientSlice.slice(1)
        : patientSlice;
      const patientSource = {
        value: b.get('pod').value + "/slices/" + normalizedPatientSlice + "/query",
        type: "graphql",
        context: {
          schema: Schemas.PATIENT_SLICE_SCHEMA,
          context: Schemas.PATIENT_SLICE_CONTEXT
        }
      };

      const barProcedureSource = {
        value: b.get('pod').value + "/slices/" + barProcedureSlice + "/query",
        type: "graphql",
        context: {
          schema: Schemas.BAR_PROCEDURE_SLICE_SCHEMA,
          context: Schemas.BAR_PROCEDURE_SLICE_CONTEXT
        }
      };

      const kneeProcedureSource = {
        value: b.get('pod').value + "/slices/" + kneeProcedureSlice + "/query",
        type: "graphql",
        context: {
          schema: Schemas.KNEE_PROCEDURE_SLICE_SCHEMA,
          context: Schemas.KNEE_PROCEDURE_SLICE_CONTEXT
        }
      };

      const weightSource = {
        value: b.get('pod').value + "/slices/" + weightSlice + "/query",
        type: "graphql",
        context: {
          schema: Schemas.WEIGHT_SLICE_SCHEMA,
          context: Schemas.WEIGHT_SLICE_CONTEXT
        }
      };

      const oxfordSource = {
        value: b.get('pod').value + "/slices/" + oxfordSlice + "/query",
        type: "graphql",
        context: {
          schema: Schemas.OXFORD_SLICE_SCHEMA,
          context: Schemas.OXFORD_SLICE_CONTEXT
        }
      };

      if (isAddition(b)) {
        console.log('[querySources] Received addition:', b.toString());
        patientSourceIterator.addSource(patientSource);
        barProcedureSourceIterator.addSource(barProcedureSource);
        kneeProcedureSourceIterator.addSource(kneeProcedureSource);
        weightSourceIterator.addSource(weightSource);
        oxfordSourceIterator.addSource(oxfordSource);
      } else {
        console.log('[querySources] Received deletion:', b.toString());
        patientSourceIterator.removeSource(patientSource);
        barProcedureSourceIterator.removeSource(barProcedureSource);
        kneeProcedureSourceIterator.removeSource(kneeProcedureSource);
        weightSourceIterator.removeSource(weightSource);
        oxfordSourceIterator.removeSource(oxfordSource);

        if (b.has('patient')) {
          const patientID = b.get('patient').value;
          console.log(`[querySources] Removing inactive patient ${patientID}`);
          await wMutex.runExclusive(() => wDist.removePatient(patientID));
          await oMutex.runExclusive(() => oDist.removePatient(patientID));
        } else {
          console.warn(
            '[querySources] Source deletion has no patient binding; projections were not cleaned:',
            b.toString(),
          );
        }
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

/**
 * Streams patient identities into both projections. The optional pseudo
 * identifier joins procedure/observation slices that do not use the patient URI.
 * Deletions here are deliberately ignored: patient activity is owned by the
 * HCP source query, while this stream can also delete bindings during identifier
 * changes. Removing a whole patient for an identifier update would be incorrect.
 */
export async function queryPatients(
  sourceIterator: QuerySourceIterator,
  wMutex: Mutex,
  wDist: WeightDistribution,
  oMutex: Mutex,
  oDist: OxfordScoreDistribution
) {
  const engine = new QueryEngine();
  console.log(`[queryPatients] Starting patients query`);

  const bindingsStream = await engine.queryBindings(Schemas.PATIENT_QUERY, {
    sources: [{
      value: sourceIterator,
      type: "stream-graphql"
    } as any],
    fetch: umaProxyFetch
  });

  bindingsStream.on('data', async (b) => {
    if (!b.has('patient')) {
      console.warn('[queryPatients] Ignoring binding without patient:', b.toString());
      return;
    }

    const patientID = b.get('patient').value;

    if (isAddition(b)) {
      console.log('[queryPatients] Received addition:', b.toString());
      if (b.has('idValue') && b.has('issuer')) {
        const ID = b.get('idValue').value;
        const issuer = b.get('issuer').value;
        await wMutex.runExclusive(() => wDist.addPatientIdentifier(patientID, ID, issuer));
        await oMutex.runExclusive(() => oDist.addPatientIdentifier(patientID, ID, issuer));
      } else {
        await wMutex.runExclusive(() => wDist.addPatientIdentifier(patientID));
        await oMutex.runExclusive(() => oDist.addPatientIdentifier(patientID));
      }
    } else {
      console.log('[queryPatients] Ignoring patient-detail deletion:', b.toString());
    }
  });

  bindingsStream.on('end', () => {
    console.log('[queryPatients] Patient stream ended');
  });

  bindingsStream.on('error', (err) => {
    console.log('[queryPatients] Patient stream error: ', err);
  });
}

/** Streams weight observations into the weight projection. */
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

/**
 * Streams individual Oxford questionnaire answers into the Oxford projection.
 * A response becomes visible in the aggregate only after all 12 answers arrive.
 */
export async function queryOxfordResponses(sourceIterater: QuerySourceIterator, dist: OxfordScoreDistribution, mutex: Mutex) {
  const engine = new QueryEngine();
  console.log('[queryOxfordResponses] Starting oxford response query');

  const bindingsStream = await engine.queryBindings(Schemas.OXFORD_QUERY, {
    sources: [{
      value: sourceIterater,
      type: "stream-graphql"
    } as any],
    fetch: umaProxyFetch
  });

  bindingsStream.on('data', async (b) => {
    if (isAddition(b)) {
      console.log('[queryOxfordResponses] Received addition:', b.toString());
      if (b.has('res') && b.has('timestamp') && b.has('patient') && b.has('value') && b.has('question')) {
        const res = b.get('res').value
        const timestamp = new Date(b.get('timestamp').value);
        const patientID = b.get('patient').value;
        const value = b.get('value').value;
        const question = b.get('question').value

        console.log(`[queryOxfordResponses] Adding answer for patient ${patientID}: response=${res}, question=${question}, timestamp=${timestamp.toISOString()}`);
        await mutex.runExclusive(() => dist.addPartialAnswer(patientID, res, timestamp, question, value));
      }
    }
  });

  bindingsStream.on('end', () => {
    console.log('[queryOxfordResponses] Oxford response stream ended');
  });

  bindingsStream.on('error', (err) => {
    console.log('[queryOxfordResponses] Oxford response stream error: ', err)
  });
}

/** Streams procedure dates into either projection. */
export async function queryProcedures(sourceIterater: QuerySourceIterator, dist: WeightDistribution | OxfordScoreDistribution, mutex: Mutex) {
  const engine = new QueryEngine();
  console.log('[queryProcedures] Starting procedure query');

  const bindingsStream = await engine.queryBindings(Schemas.PROCEDURE_QUERY, {
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

/**
 * Fetch adapter used by every query engine.
 *
 * With HTTP_PROXY/http_proxy set, requests are encoded for the Aggregator UMA
 * proxy's POST /fetch endpoint. Without it, native fetch is used. Failures use
 * unbounded exponential retry (1 second to 5 minutes); this favours eventual
 * recovery, but a permanently invalid endpoint will keep retrying forever.
 */
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
