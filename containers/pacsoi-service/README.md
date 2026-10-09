# PACSOI service

PACSOI is a long-running aggregation service that reads incremental patient data
from Kvasir slice endpoints and exposes two anonymous, population-level CSV
distributions:

- weights by calendar month relative to a bariatric procedure; and
- OWLQOL and WRSM scores at five bariatric follow-up points.

## How it works

```text
HCP active-patients HTTP API
      |
      | periodic `{ id, pod_id }` snapshots
      v
patient / procedure / weight / bariatric questionnaire slice queries
      |
      | incremental SPARQL bindings
      v
identifier resolution and out-of-order event buffers
      |
      +--> WeightDistribution ----> GET /w-dist
      |
      +--> BariatricScoreDistribution -> GET /b-dist
```

At startup, `src/index.ts` validates configuration, creates four dynamic source
iterators, starts the incremental queries, and starts Fastify on port 3000.
`src/query.ts` polls the HCP active-patients endpoint and reconciles each
successful snapshot with the previous one. For every discovered patient pod it
attaches the patient, procedure, measurement, and questionnaire slices to their
iterators. Patients missing from a later snapshot have their sources and
in-memory contributions removed.

The patient query maps canonical patient URIs and pseudo identifiers to internal
records. A record may contain multiple patient URIs. When two records contain
the same identifier value from the same issuer, they are merged under a new
record ID. Procedure and observation streams can use either form. Since the
streams are independent, their events may arrive in any order. The distribution
classes buffer procedures, weights, and questionnaire answers until the patient
mapping is known. Weight observations also wait for a bariatric procedure date.

Each observation is assigned to a relative **calendar month**:

```text
(observation year - procedure year) * 12
  + observation month - procedure month
```

Days and times are intentionally ignored. Pre-procedure data has a negative month.

For each month the output contains the population mean, population standard
deviation (division by `N`), linearly interpolated 25th and 75th percentiles,
and number of observations or completed questionnaires.

### Bariatric questionnaire score calculation

A combined response is counted only when all 17 OWLQOL items and all 20 WRSM
presence items are present. A WRSM bother answer is additionally required for
every symptom marked present.

- OWLQOL responses range from 0 to 6. They are reversed and transformed to a
  0-100 score: `(102 - raw sum) / 102 * 100`. Higher is better.
- Unsuffixed `WRSM1` through `WRSM20` are yes/no symptom-presence answers used
  to calculate the total bother score; no separate presence score is exposed.
- WRSM bother is the sum of the 0-6 bother ratings for symptoms marked present.
  The source model uses `WRSM1a` and `WRSM2a`, followed by `WRSM3b` through
  `WRSM20b`. An absent symptom contributes zero and does not require a bother
  answer. Lower WRSM scores are better.

The questionnaire URI assigns each response to `preop`, `6w`, `3m`, `6m`, or
`1y`. For each point and score, the service calculates the average, median,
population standard deviation, and linearly interpolated 25th and 75th
percentiles. Those ordered averages form the population evolution curves.

## Configuration

The team, poll interval, and proxy are optional. The team endpoint is required
only when a team is configured; all other variables are required.

| Variable | Meaning | Example |
| --- | --- | --- |
| `ACTIVE_PATIENTS_URL` | Endpoint returning an array of `{ id, pod_id }` objects | `https://pacsoi-services.faqir.org/hcps/active_patients` |
| `TEAM_ACTIVE_PATIENTS_URL` | Endpoint used instead when `TEAM_URI` is set | `https://pacsoi-services.faqir.org/hcps/teams/active_patients` |
| `ACTIVE_PATIENTS_POLL_INTERVAL_MS` | Delay between successful polls (default: 60000 ms) | `60000` |
| `TEAM_URI` | Team URI used to scope active-patient discovery | `https://ns.faqir.org/teams/1` |
| `LOG_LEVEL` | Set to `debug` to include per-attempt proxy dispatch details | `info` |
| `POD_BASE_URL` | Kvasir base URL used to expand relative `pod_id` values | `https://pacsoi-kvasir.faqir.org` |
| `PATIENT_SLICE` | Patient demographics/identifier slice name | `PatientSlice` |
| `BAR_PROCEDURE_SLICE` | Bariatric procedure slice name | `BariatricProcedureSlice` |
| `WEIGHT_SLICE` | Weight observation slice name | `WeightObservationsSlice` |
| `QUESTIONNAIRE_PREOP_SLICE` | Completed preoperative response slice | `PreopBariatricResponseSlice` |
| `QUESTIONNAIRE_POSTOP6W_SLICE` | Completed 6-week response slice | `Postop6wBariatricResponseSlice` |
| `QUESTIONNAIRE_POSTOP3M_SLICE` | Completed 3-month response slice | `Postop3mBariatricResponseSlice` |
| `QUESTIONNAIRE_POSTOP6M_SLICE` | Completed 6-month response slice | `Postop6mBariatricResponseSlice` |
| `QUESTIONNAIRE_POSTOP1Y_SLICE` | Completed 1-year response slice | `Postop1yBariatricResponseSlice` |

Slice names may be supplied with or without a leading slash. A relative
`pod_id` is resolved to `<POD_BASE_URL>/<pod_id>`; an absolute `pod_id` is used
as-is. Patient slice URLs are then built as
`<pod-url>/slices/<slice-name>/query`.

When `TEAM_URI` is set, patient pods are fetched from
`TEAM_ACTIVE_PATIENTS_URL` with the URL-encoded URI added as its `team_uri`
query parameter. When it is unset, `ACTIVE_PATIENTS_URL` is used as-is.

When `EGRESS_UMA_URL` is configured, outbound requests are sent to `<proxy>/fetch`
as a JSON request envelope. Active-patient polls request the proxy's `oauth`
mode, which sends the user's Bearer token immediately without attempting UMA.
Patient-pod slice requests use the default `auto` mode. Without a proxy, requests
are fetched directly. Failed fetches retry indefinitely with exponential
backoff, beginning at one second and capped at five minutes. A pod or
authorization problem therefore does not terminate the process; look for
repeated `[FETCH] Attempt ... failed` messages.

## HTTP API

Both endpoints return a point-in-time snapshot under the corresponding mutex.
An empty projection returns only its header row.

### `GET /w-dist`

```csv
month,avg_weight,stdev,q25,q75,count
0,104.50,2.50,103.25,105.75,2
1,99.00,0.00,99.00,99.00,1
```

### `GET /b-dist`

```csv
timepoint,owlqol_avg,owlqol_median,owlqol_stddev,owlqol_q25,owlqol_q75,wrsm_bother_avg,wrsm_bother_median,wrsm_bother_stddev,wrsm_bother_q25,wrsm_bother_q75,count
preop,54.90,54.90,0.00,54.90,54.90,6.00,6.00,0.00,6.00,6.00,1
```

There is currently no health endpoint. A successful TCP connection or either
CSV endpoint can be used as a basic liveness check; a header-only CSV proves the
HTTP process is running but not that source data was received.

## Code map

| File | Responsibility |
| --- | --- |
| `src/index.ts` | Configuration, lifecycle, mutex ownership, and HTTP routes |
| `src/query.ts` | Incremental query setup, binding validation, source discovery, UMA proxy fetch and retries |
| `src/schemas.ts` | GraphQL-LD schemas, JSON-LD contexts, and SPARQL `SELECT` queries |
| `src/weight-dist.ts` | Identifier resolution, out-of-order buffers, weight buckets, statistics, and CSV |
| `src/bariatric-scores.ts` | OWLQOL/WRSM answer validation and score calculation |
| `src/bariatric-dist.ts` | Identity resolution, response buffers, follow-up buckets, statistics, and CSV |
| `Dockerfile` | Two-stage Node.js 22 production image |

The SPARQL variable names in `src/schemas.ts` and the binding names read in
`src/query.ts` must change together. Questionnaire IDs, question codes, and
numeric answer ranges must match the source questionnaire exactly.

## Debugging guide

Logs use a component prefix. Follow them in this order when an output is empty:

1. `[MAIN]` confirms startup. A missing required environment variable terminates
   the process immediately with its name.
2. `[querySources]` reports every active-patient poll and every added, removed,
   or moved patient. If it does not, check `ACTIVE_PATIENTS_URL`, the returned
   JSON shape, and proxy access.
3. `[FETCH f-N]` identifies one logical request across all retry attempts. Its
   lifecycle logs include the pod, slice, status, duration, and recovery state.
   Repeated identical failures are sampled at attempts 1, 2, 4, 8, and so on;
   set `LOG_LEVEL=debug` to include each direct or proxied dispatch.
4. `[queryPatients]` should register canonical and pseudo identifiers. Without
   these, procedure/observation events remain buffered. Identifier deletions
   unlink only that identifier; they do not deactivate the complete patient.
5. `[queryProcedures]` should establish the baseline procedure. When identity
   resolution merges records with different procedures, the earliest is used
   and a warning is logged.
6. `[queryWeights]` and `[queryBariatricResponses]` confirm source bindings. The
   distribution logs then say whether data was buffered or assigned to a month.
7. `[getStats]` and `[toCSV]` report how many populated month rows were emitted.

## Important operational limitations

- State is process-local and not persisted. More than one replica would produce
  independent snapshots, so the deployment intentionally uses one replica.
- Fetch retries have no attempt limit and no per-request timeout.
- A patient missing from a successful active-patient poll has its discovered pod
  sources and complete in-memory projection removed from both distributions.
  Each pod owns a dedicated patient query so canonical patient URIs discovered
  in its data can be removed even when the active-patient API uses an unrelated
  identity. Failed or malformed polls retain the last successful source set.
  Patient-slice pseudo-identifier deletion events unlink that identifier without
  removing the complete patient. The procedure, weight, and questionnaire
  slices expose addition subscriptions only; their data is removed as part of
  whole-patient cleanup when the active-patient API removes that pod.
- All procedure bindings are retained per internal record; the earliest is the
  effective baseline. Adding an earlier procedure re-buckets existing weights
  against the new baseline.
- Buffered data has no expiry or size limit. Missing patient/procedure events can
  therefore grow memory usage over a long run.
- Data is held at observation level: `count` is the number of weights or completed
  responses, not the number of distinct patients.

These constraints are especially useful hypotheses when a restarted instance,
a scaled deployment, or a long-running instance produces surprising results.
