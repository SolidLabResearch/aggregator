# PACSOI service

PACSOI is a long-running aggregation service that reads incremental patient data
from Kvasir slice endpoints and exposes two anonymous, population-level CSV
distributions:

- weights by calendar month relative to a bariatric procedure; and
- Oxford Knee Scores by calendar month relative to a knee procedure.

The implementation from commit `25598a3`, before the patient identity and
removal changes, is preserved as the separately buildable
[`pacsoi-service-legacy`](../pacsoi-service-legacy/README.md) fallback.

## How it works

```text
doctor HCP slice
      |
      | discovers patient pod URLs
      v
patient / procedure / weight / Oxford slice queries
      |
      | incremental SPARQL bindings
      v
identifier resolution and out-of-order event buffers
      |
      +--> WeightDistribution ----> GET /w-dist
      |
      +--> OxfordScoreDistribution -> GET /o-dist
```

At startup, `src/index.ts` validates configuration, creates five dynamic source
iterators, starts the incremental queries, and starts Fastify on port 3000.
`src/query.ts` first watches the doctor's HCP slice. For each patient pod it
discovers, it attaches the patient, procedure, measurement, and questionnaire
slices to their iterators.

The patient query maps the canonical patient URI and any pseudo identifiers to
one patient. Procedure and observation streams can use either form. Since the
streams are independent, their events may arrive in any order. The distribution
classes buffer procedures, weights, and questionnaire answers until the patient
mapping and relevant procedure date are known.

Each observation is assigned to a relative **calendar month**:

```text
(observation year - procedure year) * 12
  + observation month - procedure month
```

Days and times are intentionally ignored. Pre-procedure data has a negative month.

For each month the output contains the population mean, population standard
deviation (division by `N`), linearly interpolated 25th and 75th percentiles,
and number of observations or completed questionnaires.

### Oxford score calculation

An Oxford response is counted only when all 12 expected question codes are
present. Text answers are mapped to values 0 through 4 using `VALUE_MAP` in
`src/oxford-dist.ts`, then inverted and summed (`4 - value`). The resulting
Oxford Knee Score ranges from 0 to 48, with a higher score representing a better
outcome. Unexpected questions, unknown answer text, and duplicate answers throw
an error so data/schema drift is visible in the logs.

## Configuration

All variables except the proxy are required.

| Variable | Meaning | Example |
| --- | --- | --- |
| `SOURCES` | Doctor HCP GraphQL slice query endpoint | `http://doctor-pod/slices/PatientSlice/query` |
| `PATIENT_SLICE` | Patient demographics/identifier slice name | `PatientSlice` |
| `BAR_PROCEDURE_SLICE` | Bariatric procedure slice name | `BariatricProcedureSlice` |
| `KNEE_PROCEDURE_SLICE` | Knee procedure slice name | `KneeProcedureSlice` |
| `WEIGHT_SLICE` | Weight observation slice name | `WeightObservationsSlice` |
| `OXFORD_SLICE` | Completed Oxford response slice name | `OxfordResponseSlice` |

Slice names may be supplied with or without a leading slash. Discovered patient
URLs are built as `<pod>/slices/<slice-name>/query`.

When a proxy is configured, outbound requests are sent to `<proxy>/fetch` as a
JSON request envelope. Without a proxy they are fetched directly. Failed fetches
retry indefinitely with exponential backoff, beginning at one second and capped
at five minutes. A pod or authorization problem therefore does not terminate the
process; look for repeated `[FETCH] Attempt ... failed` messages.

## HTTP API

Both endpoints return a point-in-time snapshot under the corresponding mutex.
An empty projection returns only its header row.

### `GET /w-dist`

```csv
month,avg_weight,stdev,q25,q75,count
0,104.50,2.50,103.25,105.75,2
1,99.00,0.00,99.00,99.00,1
```

### `GET /o-dist`

```csv
month,avg_score,stdev,q25,q75,count
3,36.50,1.50,35.75,37.25,2
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
| `src/oxford-dist.ts` | Questionnaire validation/scoring, buffers, score buckets, statistics, and CSV |
| `Dockerfile` | Two-stage Node.js 22 production image |

The SPARQL variable names in `src/schemas.ts` and the binding names read in
`src/query.ts` must change together. Likewise, Oxford question codes and answer
labels must match the source questionnaire exactly.

## Debugging guide

Logs use a component prefix. Follow them in this order when an output is empty:

1. `[MAIN]` confirms startup. A missing required environment variable terminates
   the process immediately with its name.
2. `[querySources]` should log a binding containing `pod`. If it does not, check
   `SOURCES`, the HCP schema/query, and doctor-to-patient relationships.
3. `[FETCH]` shows every target, whether direct or proxied access is used, HTTP
   status failures, and retry delays. Repeated retries usually mean connectivity,
   authorization, an incorrect slice name, or an incompatible GraphQL schema.
4. `[queryPatients]` should register canonical and pseudo identifiers. Without
   these, procedure/observation events remain buffered. Detail-stream deletions
   are ignored because an identifier update must not deactivate the patient.
5. `[queryProcedures]` should establish the baseline procedure. Only the first
   procedure received per patient is used; later ones are logged and skipped.
6. `[queryWeights]` and `[queryOxfordResponses]` confirm source bindings. The
   distribution logs then say whether data was buffered or assigned to a month.
7. `[getStats]` and `[toCSV]` report how many populated month rows were emitted.

## Important operational limitations

- State is process-local and not persisted. More than one replica would produce
  independent snapshots, so the deployment intentionally uses one replica.
- Fetch retries have no attempt limit and no per-request timeout.
- Removing the doctor-to-patient relation from the HCP source query removes the
  discovered pod sources and the patient's complete in-memory projection from
  both distributions. Patient-detail or pseudo-identifier deletion events do
  not remove the patient.
- Only the first procedure encountered for a patient is retained. Event arrival
  order, rather than earliest timestamp, determines which one wins. Currently only one procedure is expected per patient, but a future version may support multiple procedures.
- Buffered data has no expiry or size limit. Missing patient/procedure events can
  therefore grow memory usage over a long run.
- Data is held at observation level: `count` is the number of weights or completed
  responses, not the number of distinct patients.

These constraints are especially useful hypotheses when a restarted instance,
a scaled deployment, or a long-running instance produces surprising results.
