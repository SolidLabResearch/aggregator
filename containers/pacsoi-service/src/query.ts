import { QueryEngine } from "@incremunica/query-sparql-incremental";
import { isAddition, QuerySourceIterator } from '@incremunica/user-tools';
import * as Schemas from "./schemas.js";
import { WeightDistribution } from "./weight-dist.js";
import { Mutex } from "async-mutex";
import { BariatricScoreDistribution } from "./bariatric-dist.js";

export interface QuestionnaireSliceSource {
  slice: string;
  schema: string;
}

export interface ActivePatient {
  id: string;
  pod_id: string;
}

type DynamicQuerySource = Parameters<QuerySourceIterator["addSource"]>[0];

interface PatientSourceBundle {
  podID: string;
  podURL: string;
  ownership: PatientSourceOwnership;
  patientSource: DynamicQuerySource;
  stopPatientQuery?: () => void;
  barProcedureSource: DynamicQuerySource;
  weightSource: DynamicQuerySource;
  questionnaireSources: DynamicQuerySource[];
}

/** Tracks the projection identities discovered through one patient's pod. */
export class PatientSourceOwnership {
  private active = true;
  private readonly patientIDs = new Set<string>();

  constructor(
    public readonly podURL: string,
    activePatientID: string,
  ) {
    // Also retain the API identity so its placeholder projection record is
    // removed together with the canonical identities found in the pod.
    this.patientIDs.add(activePatientID);
  }

  track(patientID: string): boolean {
    if (!this.active) return false;
    this.patientIDs.add(patientID);
    return true;
  }

  deactivate(): string[] {
    this.active = false;
    return [...this.patientIDs];
  }
}

/** Validates the response returned by GET /hcps/active_patients. */
export function parseActivePatients(payload: unknown): ActivePatient[] {
  if (!Array.isArray(payload)) {
    throw new Error("Active-patient response must be an array");
  }

  const patients = new Map<string, ActivePatient>();
  for (const [index, value] of payload.entries()) {
    if (
      typeof value !== "object" ||
      value === null ||
      typeof (value as Record<string, unknown>).id !== "string" ||
      !(value as Record<string, unknown>).id ||
      typeof (value as Record<string, unknown>).pod_id !== "string" ||
      !(value as Record<string, unknown>).pod_id
    ) {
      throw new Error(`Active-patient response item ${index} must contain non-empty id and pod_id strings`);
    }

    const raw = value as unknown as ActivePatient;
    const patient = {
      id: raw.id,
      pod_id: raw.pod_id.replace(/\/+$/, ""),
    };
    if (!patient.pod_id) {
      throw new Error(`Active-patient response item ${index} contains an invalid pod_id`);
    }
    const previous = patients.get(patient.id);
    if (previous && previous.pod_id !== patient.pod_id) {
      throw new Error(`Active-patient response contains conflicting pods for patient ${patient.id}`);
    }
    patients.set(patient.id, patient);
  }

  return [...patients.values()];
}

/** Resolves either an absolute pod URL or a pod identifier below a Kvasir base URL. */
export function resolvePodURL(podID: string, podBaseURL: string): string {
  try {
    const absolute = new URL(podID);
    if (absolute.protocol !== "http:" && absolute.protocol !== "https:") {
      throw new Error(`Unsupported pod URL protocol: ${absolute.protocol}`);
    }
    return absolute.toString().replace(/\/+$/, "");
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("Unsupported pod URL protocol:")) {
      throw error;
    }
  }

  const base = new URL(podBaseURL.endsWith("/") ? podBaseURL : podBaseURL + "/");
  if (base.protocol !== "http:" && base.protocol !== "https:") {
    throw new Error(`Unsupported pod base URL protocol: ${base.protocol}`);
  }
  return new URL(encodeURIComponent(podID) + "/", base).toString().replace(/\/+$/, "");
}

/**
 * Polls the HCP API and turns every active patient's pod into live GraphQL
 * sources. Each successful response is reconciled with the previous one.
 * Failed or malformed responses leave the last known source set intact.
 *
 * Slice names passed here must not start with a slash (normalised by index.ts),
 * except patientSlice, which is accepted in either form for compatibility.
 */
export async function querySources(
  endpoint: string,
  podBaseURL: string,
  patientSlice: string,
  barProcedureSlice: string,
  barProcedureSourceIterator: QuerySourceIterator,
  weightSlice: string,
  weightSourceIterator: QuerySourceIterator,
  questionnaireSlices: QuestionnaireSliceSource[],
  questionnaireSourceIterator: QuerySourceIterator,
  wMutex: Mutex,
  wDist: WeightDistribution,
  bMutex: Mutex,
  bDist: BariatricScoreDistribution,
  pollIntervalMs: number,
) {
  console.log(`[querySources] Polling ${endpoint} every ${pollIntervalMs}ms`);
  const activeSources = new Map<string, PatientSourceBundle>();
  const normalizedPatientSlice = patientSlice.startsWith("/")
    ? patientSlice.slice(1)
    : patientSlice;

  const createSources = (patient: ActivePatient): PatientSourceBundle => {
    const base = resolvePodURL(patient.pod_id, podBaseURL);
    return {
      podID: patient.pod_id,
      podURL: base,
      ownership: new PatientSourceOwnership(base, patient.id),
      patientSource: {
        value: base + "/slices/" + normalizedPatientSlice + "/query",
        type: "graphql",
        context: {
          schema: Schemas.PATIENT_SLICE_SCHEMA,
          context: Schemas.PATIENT_SLICE_CONTEXT
        }
      },
      barProcedureSource: {
        value: base + "/slices/" + barProcedureSlice + "/query",
        type: "graphql",
        context: {
          schema: Schemas.BAR_PROCEDURE_SLICE_SCHEMA,
          context: Schemas.BAR_PROCEDURE_SLICE_CONTEXT
        }
      },
      weightSource: {
        value: base + "/slices/" + weightSlice + "/query",
        type: "graphql",
        context: {
          schema: Schemas.WEIGHT_SLICE_SCHEMA,
          context: Schemas.WEIGHT_SLICE_CONTEXT
        }
      },
      questionnaireSources: questionnaireSlices.map(({ slice, schema }) => ({
        value: base + "/slices/" + slice + "/query",
        type: "graphql",
        context: {
          schema,
          context: Schemas.QUESTIONNAIRE_SLICE_CONTEXT,
        }
      })),
    };
  };

  const addSources = async (sources: PatientSourceBundle) => {
    sources.stopPatientQuery = await queryPatients(
      sources.patientSource,
      wMutex,
      wDist,
      bMutex,
      bDist,
      patientID => sources.ownership.track(patientID),
    );
    barProcedureSourceIterator.addSource(sources.barProcedureSource);
    weightSourceIterator.addSource(sources.weightSource);
    for (const source of sources.questionnaireSources) {
      questionnaireSourceIterator.addSource(source);
    }
  };

  const removeSources = (sources: PatientSourceBundle) => {
    sources.stopPatientQuery?.();
    barProcedureSourceIterator.removeSource(sources.barProcedureSource);
    weightSourceIterator.removeSource(sources.weightSource);
    for (const source of sources.questionnaireSources) {
      questionnaireSourceIterator.removeSource(source);
    }
  };

  for (;;) {
    try {
      const response = await umaProxyFetch(endpoint, {
        headers: { Accept: "application/json" },
      }, "oauth");
      const patients = parseActivePatients(await response.json());
      const nextPatients = new Map(patients.map((patient) => [patient.id, patient]));

      for (const [patientID, sources] of activeSources) {
        const next = nextPatients.get(patientID);
        if (!next || next.pod_id !== sources.podID) {
          console.log(`[querySources] Removing inactive or moved patient ${patientID} (${sources.podID})`);
          const ownedPatientIDs = sources.ownership.deactivate();
          removeSources(sources);
          activeSources.delete(patientID);
          for (const ownedPatientID of ownedPatientIDs) {
            await wMutex.runExclusive(() => wDist.removePatient(ownedPatientID));
            await bMutex.runExclusive(() => bDist.removePatient(ownedPatientID));
          }
        }
      }

      for (const patient of patients) {
        if (!activeSources.has(patient.id)) {
          console.log(`[querySources] Adding active patient ${patient.id} (${patient.pod_id})`);
          await wMutex.runExclusive(() => wDist.addPatientIdentifier(patient.id));
          await bMutex.runExclusive(() => bDist.addPatientIdentifier(patient.id));
          const sources = createSources(patient);
          await addSources(sources);
          activeSources.set(patient.id, sources);
        }
      }

      console.log(`[querySources] Active-patient poll complete: ${activeSources.size} patient(s)`);
    } catch (error) {
      console.warn(
        `[querySources] Active-patient poll failed; retaining previous sources: ${(error as Error).message}`,
      );
    }

    await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
  }
}

/**
 * Streams patient identities into both projections. The optional pseudo
 * identifier joins procedure/observation slices that do not use the patient URI.
 * Deletions remove the affected pseudo-identifier link. They do not remove the
 * complete patient: patient activity and full projection cleanup are owned by
 * the active-patient API and its per-pod ownership tracker.
 */
export async function queryPatients(
  source: DynamicQuerySource,
  wMutex: Mutex,
  wDist: WeightDistribution,
  bMutex: Mutex,
  bDist: BariatricScoreDistribution,
  trackPatient: (patientID: string) => boolean,
): Promise<() => void> {
  const engine = new QueryEngine();
  console.log(`[queryPatients] Starting patients query`);

  const bindingsStream = await engine.queryBindings(Schemas.PATIENT_QUERY, {
    sources: [source as any],
    fetch: umaProxyFetch
  });

  bindingsStream.on('data', async (b) => {
    if (!b.has('patient')) {
      console.warn('[queryPatients] Ignoring binding without patient:', b.toString());
      return;
    }

    const patientID = b.get('patient').value;

    if (isAddition(b)) {
      // The bundle may have been removed while this event was in flight.
      if (!trackPatient(patientID)) return;
      console.log('[queryPatients] Received addition:', b.toString());
      if (b.has('idValue') && b.has('issuer')) {
        const ID = b.get('idValue').value;
        const issuer = b.get('issuer').value;
        await wMutex.runExclusive(() => wDist.addPatientIdentifier(patientID, ID, issuer));
        await bMutex.runExclusive(() => bDist.addPatientIdentifier(patientID, ID, issuer));
      } else {
        await wMutex.runExclusive(() => wDist.addPatientIdentifier(patientID));
        await bMutex.runExclusive(() => bDist.addPatientIdentifier(patientID));
      }
    } else {
      console.log('[queryPatients] Received deletion:', b.toString());
      if (b.has('idValue') && b.has('issuer')) {
        const ID = b.get('idValue').value;
        const issuer = b.get('issuer').value;
        await wMutex.runExclusive(() => wDist.removePatientIdentifier(patientID, ID, issuer));
        await bMutex.runExclusive(() => bDist.removePatientIdentifier(patientID, ID, issuer));
      }
    }
  });

  bindingsStream.on('end', () => {
    console.log('[queryPatients] Patient stream ended');
  });

  bindingsStream.on('error', (err) => {
    console.log('[queryPatients] Patient stream error: ', err);
  });

  return () => bindingsStream.destroy();
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
    if (b.has('observation') && b.has('value') && b.has('timestamp') && b.has('patient')) {
      const observationID = b.get('observation').value;
      const value = parseFloat(b.get('value').value);
      const timestamp = new Date(b.get('timestamp').value);
      const patientID = b.get('patient').value;

      console.log('[queryWeights] Received addition:', b.toString());
      console.log(`[queryWeights] Adding weight observation for patient ${patientID}: value=${value}, timestamp=${timestamp.toISOString()}`);
      await mutex.runExclusive(() => dist.addWeightObservation(patientID, observationID, value, timestamp));
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
 * Streams individual OWLQOL and WRSM answers into the bariatric projection.
 * A response becomes visible only after both questionnaire scores are complete.
 */
export async function queryBariatricResponses(
  sourceIterater: QuerySourceIterator,
  dist: BariatricScoreDistribution,
  mutex: Mutex,
) {
  const engine = new QueryEngine();
  console.log('[queryBariatricResponses] Starting bariatric response query');

  const bindingsStream = await engine.queryBindings(Schemas.QUESTIONNAIRE_QUERY, {
    sources: [{
      value: sourceIterater,
      type: "stream-graphql"
    } as any],
    fetch: umaProxyFetch
  });

  bindingsStream.on('data', async (b) => {
    if (b.has('res') && b.has('patient') && b.has('questionnaire') && b.has('value') && b.has('question')) {
      const res = b.get('res').value;
      const patientID = b.get('patient').value;
      const questionnaire = b.get('questionnaire').value;
      const value = b.get('value').value;
      const question = b.get('question').value;

      console.log('[queryBariatricResponses] Received addition:', b.toString());
      console.log(`[queryBariatricResponses] Adding answer for patient ${patientID}: response=${res}, questionnaire=${questionnaire}, question=${question}`);
      try {
        await mutex.runExclusive(() =>
          dist.addPartialAnswer(patientID, res, questionnaire, question, value),
        );
      } catch (error) {
        console.error(
          `[queryBariatricResponses] Failed to add answer response=${res} question=${question}: ${(error as Error).message}`,
        );
      }
    } else {
      console.warn('[queryBariatricResponses] Ignoring incomplete binding:', b.toString());
    }
  });

  bindingsStream.on('end', () => {
    console.log('[queryBariatricResponses] Bariatric response stream ended');
  });

  bindingsStream.on('error', (err) => {
    console.log('[queryBariatricResponses] Bariatric response stream error: ', err)
  });
}

/** Streams bariatric procedure dates into the weight projection. */
export async function queryProcedures(sourceIterater: QuerySourceIterator, dist: WeightDistribution, mutex: Mutex) {
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
    if (b.has('procedure') && b.has('timestamp') && b.has('patient')) {
      const procedureID = b.get('procedure').value;
      const timestamp = new Date(b.get('timestamp').value);
      const patientID = b.get('patient').value;

      console.log('[queryProcedures] Received addition:', b.toString());
      console.log(`[queryProcedures] Adding procedure for patient ${patientID}: timestamp=${timestamp.toISOString()}`);
      await mutex.runExclusive(() => dist.addPatientProcedure(patientID, procedureID, timestamp));
    }
  });
}

let nextFetchID = 1;

export interface FetchTargetDescription {
  target: string;
  pod?: string;
  slice?: string;
}

/** Extracts stable, useful labels without logging URL query parameters. */
export function describeFetchTarget(target: string): FetchTargetDescription {
  try {
    const url = new URL(target);
    const parts = url.pathname.split("/").filter(Boolean).map(decodeURIComponent);
    const slicesIndex = parts.indexOf("slices");
    return {
      target: url.origin + url.pathname,
      pod: slicesIndex > 0 ? parts[slicesIndex - 1] : undefined,
      slice: slicesIndex >= 0 ? parts[slicesIndex + 1] : undefined,
    };
  } catch {
    return { target };
  }
}

/** Logs unchanged failures on attempts 1, 2, 4, 8, ... instead of every retry. */
export function shouldLogFetchFailure(attempt: number, changed: boolean): boolean {
  return changed || attempt === 1 || (attempt & (attempt - 1)) === 0;
}

class FetchResponseError extends Error {
  constructor(
    public readonly status: number,
    public readonly reason: string,
  ) {
    super(`Response not ok: ${status}${reason ? ` ${reason}` : ""}`);
  }
}

function fetchLog(
  level: "debug" | "info" | "warn",
  requestID: string,
  event: string,
  fields: Record<string, unknown> = {},
): void {
  if (level === "debug" && (process.env.LOG_LEVEL ?? "info").toLowerCase() !== "debug") return;
  const details = Object.entries(fields)
    .filter(([, value]) => value !== undefined && value !== "")
    .map(([key, value]) => `${key}=${JSON.stringify(value)}`)
    .join(" ");
  const line = `[FETCH ${requestID}] ${event}${details ? ` ${details}` : ""}`;
  if (level === "warn") console.warn(line);
  else if (level === "debug") console.debug(line);
  else console.info(line);
}

function fetchFailureReason(body: string, statusText: string): string {
  const trimmed = body.trim();
  if (trimmed) {
    try {
      const parsed = JSON.parse(trimmed) as Record<string, unknown>;
      const reason = parsed.message ?? parsed.description ?? parsed.error;
      if (typeof reason === "string" && reason.trim()) return reason.trim();
    } catch {
      // Keep the compact plain-text response below.
    }
    return trimmed.replace(/\s+/g, " ").slice(0, 200);
  }
  return statusText;
}

/**
 * Fetch adapter used by every query engine. A stable request ID covers all
 * retry attempts and is forwarded to egress-UMA for cross-service correlation.
 */
async function umaProxyFetch(
  input: RequestInfo | URL,
  init?: RequestInit,
  authMode: "auto" | "oauth" = "auto",
): Promise<Response> {
  let target = input.toString();
  const originalUrl = target;
  const requestID = `f-${nextFetchID++}`;
  const targetDescription = describeFetchTarget(originalUrl);
  const BASE_DELAY_MS = 1000;
  const MAX_DELAY_MS = 300000;
  const BACKOFF_FACTOR = 2;
  const startedAt = Date.now();
  let lastFailure = "";
  let suppressedFailures = 0;

  const acceptHeader = init?.headers ? new Headers(init.headers).get("Accept") : undefined;
  const isStream = acceptHeader === "text/event-stream";
  const method = init?.method || "GET";

  fetchLog("info", requestID, "start", {
    method,
    auth: authMode,
    stream: isStream,
    pod: targetDescription.pod,
    slice: targetDescription.slice,
    target: targetDescription.pod ? undefined : targetDescription.target,
  });

  for (let attempt = 0; ; attempt++) {
    const delay = Math.min(BASE_DELAY_MS * BACKOFF_FACTOR ** attempt, MAX_DELAY_MS);
    const attemptNumber = attempt + 1;

    try {
      let response: Response;
      const egressUmaUrl = process.env.EGRESS_UMA_URL?.replace(/\/+$/, "");
      if (!egressUmaUrl) {
        fetchLog("debug", requestID, "dispatch", { attempt: attemptNumber, via: "direct" });
        response = await fetch(input, init);
      } else {
        fetchLog("debug", requestID, "dispatch", { attempt: attemptNumber, via: "egress-uma" });
        target = egressUmaUrl + "/fetch";

        const bodyHeaders: Record<string, string> = {};
        if (init?.headers) {
          if (init.headers instanceof Headers) {
            init.headers.forEach((value, key) => (bodyHeaders[key] = value));
          } else if (Array.isArray(init.headers)) {
            init.headers.forEach(([key, value]) => (bodyHeaders[key] = value));
          } else {
            Object.assign(bodyHeaders, init.headers);
          }
        }
        if (isStream) {
          bodyHeaders["Accept"] = "text/event-stream";
          bodyHeaders["Cache-Control"] = "no-cache";
          bodyHeaders["Connection"] = "keep-alive";
        }

        response = await fetch(target, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Request-ID": requestID,
          },
          body: JSON.stringify({
            url: originalUrl,
            method,
            headers: bodyHeaders,
            body: init?.body ? init.body.toString() : "",
            authMode,
          }),
        });

        Object.defineProperty(response, "url", {
          value: originalUrl,
          writable: false,
          enumerable: true,
          configurable: false,
        });
      }

      if (!response.ok) {
        const responseBody = await response.text();
        throw new FetchResponseError(
          response.status,
          fetchFailureReason(responseBody, response.statusText),
        );
      }

      fetchLog("info", requestID, isStream ? "connected" : "complete", {
        status: response.status,
        attempt: attemptNumber,
        duration_ms: Date.now() - startedAt,
        recovered: attempt > 0 || undefined,
        suppressed_failures: suppressedFailures || undefined,
      });
      return response;
    } catch (error) {
      const status = error instanceof FetchResponseError ? error.status : undefined;
      const reason = error instanceof FetchResponseError ? error.reason : (error as Error).message;
      const signature = `${status ?? "network"}:${reason}`;
      const changed = signature !== lastFailure;
      if (shouldLogFetchFailure(attemptNumber, changed)) {
        fetchLog("warn", requestID, status === 401 || status === 403 ? "denied" : "retry", {
          attempt: attemptNumber,
          status,
          reason,
          retry_in_ms: delay,
          suppressed: suppressedFailures || undefined,
        });
        suppressedFailures = 0;
      } else {
        suppressedFailures++;
      }
      lastFailure = signature;
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }
}
