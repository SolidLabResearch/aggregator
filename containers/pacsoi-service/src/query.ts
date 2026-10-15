import { QueryEngine } from "@incremunica/query-sparql-incremental";
import { isAddition, QuerySourceIterator } from '@incremunica/user-tools';
import * as Schemas from "./schemas.js";
import { WeightDistribution } from "./weight-dist.js";
import { Mutex } from "async-mutex";
import { BariatricScoreDistribution } from "./bariatric-dist.js";
import { sleep, sourceFetchScopes, umaProxyFetch } from "./fetch.js";
import { type GroupStatus, PopulationStatus, SOURCE_GROUPS, type SourceGroup } from "./population.js";

export interface QuestionnaireSliceSource {
  slice: string;
  schema: string;
}

export interface ActivePatient {
  id: string;
  pod_id: string;
}

/** Selects the configured team endpoint when a team URI is configured. */
export function activePatientsURL(
  endpoint: string,
  teamEndpoint: string | undefined,
  teamURI?: string,
): string {
  if (!teamURI) return endpoint;
  if (!teamEndpoint) {
    throw new Error("Environment variable TEAM_ACTIVE_PATIENTS_URL must be set when TEAM_URI is set");
  }

  const url = new URL(teamEndpoint);
  url.hash = "";
  url.searchParams.set("team_uri", teamURI);
  return url.toString();
}

type DynamicQuerySource = Parameters<QuerySourceIterator["addSource"]>[0];

interface GroupSource {
  source: DynamicQuerySource;
  /** The shared iterator feeding this source's query; absent for the patient slice. */
  iterator?: QuerySourceIterator;
}

interface SourceGroupState {
  sources: GroupSource[];
  active: boolean;
  /** Source URLs that answered successfully since the group was last added. */
  succeeded: Set<string>;
}

interface PatientSourceBundle {
  patientID: string;
  podID: string;
  podURL: string;
  ownership: PatientSourceOwnership;
  groups: Record<SourceGroup, SourceGroupState>;
  stopPatientQuery?: () => void;
}

function sourceURL(source: DynamicQuerySource): string {
  return typeof source === "string" ? source : (source as { value: string }).value;
}

/**
 * Decides what to suspend when one source group of a patient fails. The
 * patient slice carries the identities, so its failure suspends the whole
 * patient. Losing both data groups leaves nothing to serve, so that also
 * suspends the whole patient.
 */
export function escalate(
  failed: SourceGroup,
  suspended: ReadonlySet<SourceGroup>,
): SourceGroup {
  if (failed === "patient") return "patient";
  const other: SourceGroup = failed === "weight" ? "bariatric" : "weight";
  return suspended.has(other) ? "patient" : failed;
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

  ids(): string[] {
    return [...this.patientIDs];
  }
}

/** Validates the response returned by an HCP active-patients endpoint. */
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
 * Each patient's sources form three groups: the patient slice, the weight
 * group (procedure and weight slices), and the bariatric group (questionnaire
 * slices). A group whose source is unauthorized, keeps failing, or loses its
 * subscription is suspended: its sources are removed and its distribution data
 * for that patient is cleared. See `escalate` for when the whole patient is
 * suspended instead. Every poll is a reset point: suspended groups and patients
 * that are still active are added again from scratch.
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
  sourceAddIntervalMs = 0,
  population = new PopulationStatus(),
) {
  console.log(`[querySources] Polling ${endpoint} every ${pollIntervalMs}ms`);
  const activeSources = new Map<string, PatientSourceBundle>();
  /** Source URL -> active patients using it; patients may share a pod. */
  const sourceOwners = new Map<string, Set<string>>();
  /** Serializes poll reconciliation with source-event handling. */
  const sourcesMutex = new Mutex();
  const normalizedPatientSlice = patientSlice.startsWith("/")
    ? patientSlice.slice(1)
    : patientSlice;

  const group = (sources: GroupSource[]): SourceGroupState => ({
    sources,
    active: false,
    succeeded: new Set(),
  });

  const createSources = (patient: ActivePatient): PatientSourceBundle => {
    const base = resolvePodURL(patient.pod_id, podBaseURL);
    const slice = (name: string, schema: string, context: unknown): DynamicQuerySource => ({
      value: base + "/slices/" + name + "/query",
      type: "graphql",
      context: { schema, context },
    } as DynamicQuerySource);
    return {
      patientID: patient.id,
      podID: patient.pod_id,
      podURL: base,
      ownership: new PatientSourceOwnership(base, patient.id),
      groups: {
        patient: group([
          { source: slice(normalizedPatientSlice, Schemas.PATIENT_SLICE_SCHEMA, Schemas.PATIENT_SLICE_CONTEXT) },
        ]),
        weight: group([
          {
            source: slice(barProcedureSlice, Schemas.BAR_PROCEDURE_SLICE_SCHEMA, Schemas.BAR_PROCEDURE_SLICE_CONTEXT),
            iterator: barProcedureSourceIterator,
          },
          {
            source: slice(weightSlice, Schemas.WEIGHT_SLICE_SCHEMA, Schemas.WEIGHT_SLICE_CONTEXT),
            iterator: weightSourceIterator,
          },
        ]),
        bariatric: group(questionnaireSlices.map(({ slice: name, schema }) => ({
          source: slice(name, schema, Schemas.QUESTIONNAIRE_SLICE_CONTEXT),
          iterator: questionnaireSourceIterator,
        }))),
      },
    };
  };

  const openGroup = async (bundle: PatientSourceBundle, name: SourceGroup) => {
    const state = bundle.groups[name];
    state.active = true;
    state.succeeded.clear();
    population.set(bundle.patientID, name, "connecting");
    // Open the fetch scopes before the engines issue their first request.
    for (const { source } of state.sources) {
      const url = sourceURL(source);
      const owners = sourceOwners.get(url) ?? new Set<string>();
      owners.add(bundle.patientID);
      sourceOwners.set(url, owners);
      sourceFetchScopes.open(url);
    }
    if (name === "patient") {
      bundle.stopPatientQuery = await queryPatients(
        state.sources[0].source,
        wMutex,
        wDist,
        bMutex,
        bDist,
        patientID => bundle.ownership.track(patientID),
      );
    } else {
      for (const { source, iterator } of state.sources) iterator!.addSource(source);
    }
  };

  const closeGroup = (bundle: PatientSourceBundle, name: SourceGroup) => {
    const state = bundle.groups[name];
    if (!state.active) return;
    state.active = false;
    if (name === "patient") {
      bundle.stopPatientQuery?.();
      bundle.stopPatientQuery = undefined;
    } else {
      for (const { source, iterator } of state.sources) iterator!.removeSource(source);
    }
    // Ends pending retries and open event streams quietly. Closing after the
    // removals means any late response is ignored by the engines.
    for (const { source } of state.sources) {
      const url = sourceURL(source);
      const owners = sourceOwners.get(url);
      owners?.delete(bundle.patientID);
      if (owners?.size === 0) sourceOwners.delete(url);
      sourceFetchScopes.close(url);
    }
  };

  const removeBundle = async (bundle: PatientSourceBundle) => {
    const ownedPatientIDs = bundle.ownership.deactivate();
    for (const name of SOURCE_GROUPS) closeGroup(bundle, name);
    activeSources.delete(bundle.patientID);
    for (const ownedPatientID of ownedPatientIDs) {
      await wMutex.runExclusive(() => wDist.removePatient(ownedPatientID));
      await bMutex.runExclusive(() => bDist.removePatient(ownedPatientID));
    }
  };

  const suspend = async (
    bundle: PatientSourceBundle,
    failed: SourceGroup,
    status: GroupStatus,
    reason: string | undefined,
  ) => {
    const suspended = new Set(SOURCE_GROUPS.filter(name => !bundle.groups[name].active));
    const target = escalate(failed, suspended);
    population.set(bundle.patientID, failed, status);
    console.warn(
      `[querySources] Suspending ${target === "patient" ? "patient" : `${failed} sources`} of ` +
        `${bundle.patientID} until the next poll: ${failed} ${status}${reason ? ` (${reason})` : ""}`,
    );

    if (target === "patient") {
      // A denial applies to the whole patient, so the groups cancelled with it
      // are reported as unauthorized too. Other causes leave them "stopped":
      // they were shut down without an answer of their own.
      const cascaded: GroupStatus = status === "unauthorized" ? "unauthorized" : "stopped";
      for (const name of SOURCE_GROUPS) {
        if (name !== failed && bundle.groups[name].active) population.set(bundle.patientID, name, cascaded);
      }
      await removeBundle(bundle);
      return;
    }

    closeGroup(bundle, failed);
    for (const patientID of bundle.ownership.ids()) {
      if (failed === "weight") await wMutex.runExclusive(() => wDist.clearPatientData(patientID));
      else await bMutex.runExclusive(() => bDist.clearPatientData(patientID));
    }
  };

  sourceFetchScopes.onEvent = (url, event, reason) => {
    void sourcesMutex.runExclusive(async () => {
      for (const patientID of [...(sourceOwners.get(url) ?? [])]) {
        const bundle = activeSources.get(patientID);
        if (!bundle) continue;
        const name = SOURCE_GROUPS.find(candidate =>
          bundle.groups[candidate].active &&
          bundle.groups[candidate].sources.some(({ source }) => sourceURL(source) === url));
        if (!name) continue;
        const state = bundle.groups[name];

        if (event === "success") {
          state.succeeded.add(url);
          if (state.succeeded.size === state.sources.length) population.set(patientID, name, "ok");
          continue;
        }
        await suspend(bundle, name, event, reason);
      }
    }).catch(error => {
      console.error(`[querySources] Failed to handle ${event} for ${url}: ${(error as Error).message}`);
    });
  };

  for (;;) {
    let patients: ActivePatient[] | undefined;
    try {
      const response = await umaProxyFetch(endpoint, {
        headers: { Accept: "application/json" },
      }, "oauth");
      patients = parseActivePatients(await response.json());
    } catch (error) {
      population.pollFailed((error as Error).message);
      console.warn(
        `[querySources] Active-patient poll failed; retaining previous sources: ${(error as Error).message}`,
      );
    }

    if (patients) {
      const polled = patients;
      await sourcesMutex.runExclusive(async () => {
        population.pollSucceeded(polled.map(patient => patient.id));
        const nextPatients = new Map(polled.map((patient) => [patient.id, patient]));

        for (const [patientID, bundle] of activeSources) {
          const next = nextPatients.get(patientID);
          if (!next || next.pod_id !== bundle.podID) {
            console.log(`[querySources] Removing inactive or moved patient ${patientID} (${bundle.podID})`);
            await removeBundle(bundle);
          }
        }

        // Each source opens requests at once; spacing additions out avoids a
        // burst of requests on startup and after an outage.
        let added = 0;
        const stagger = async () => {
          if (added++ > 0 && sourceAddIntervalMs > 0) await sleep(sourceAddIntervalMs);
        };

        for (const patient of polled) {
          let bundle = activeSources.get(patient.id);
          if (!bundle) {
            await stagger();
            console.log(`[querySources] Adding active patient ${patient.id} (${patient.pod_id})`);
            await wMutex.runExclusive(() => wDist.addPatientIdentifier(patient.id));
            await bMutex.runExclusive(() => bDist.addPatientIdentifier(patient.id));
            bundle = createSources(patient);
            activeSources.set(patient.id, bundle);
            for (const name of SOURCE_GROUPS) await openGroup(bundle, name);
            continue;
          }
          for (const name of SOURCE_GROUPS) {
            if (bundle.groups[name].active) continue;
            await stagger();
            console.log(`[querySources] Re-adding ${name} sources of patient ${patient.id}`);
            await openGroup(bundle, name);
          }
        }

        console.log(`[querySources] Active-patient poll complete: ${activeSources.size} patient(s)`);
      }).catch(error => {
        console.error(`[querySources] Active-patient reconciliation failed: ${(error as Error).message}`);
      });
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
    // Weight slices are append-only. Non-additions are incremunica retracting
    // a removed source; its data is cleared by the source poller instead.
    if (!isAddition(b)) return;
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
    // Questionnaire slices are append-only; see queryWeights.
    if (!isAddition(b)) return;
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
    // Procedure slices are append-only; see queryWeights.
    if (!isAddition(b)) return;
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
