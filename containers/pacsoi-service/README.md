# PACSOI service

PACSOI is a long-running aggregation service that reads incremental patient data
from Kvasir slice endpoints and exposes two anonymous, population-level CSV
distributions:

- weights by calendar month relative to a bariatric procedure; and
- OWLQOL and WRSM scores at five bariatric follow-up points.

It also exposes population metrics: how many patients are active and how many
of their sources are connected, unauthorized, or failed.

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

The team, poll interval, k-anonymity threshold, and proxy are optional. The team endpoint is required
only when a team is configured; all other variables are required.

| Variable | Meaning | Example |
| --- | --- | --- |
| `ACTIVE_PATIENTS_URL` | Endpoint returning an array of `{ id, pod_id }` objects | `https://pacsoi-services.faqir.org/hcps/active_patients` |
| `TEAM_ACTIVE_PATIENTS_URL` | Endpoint used instead when `TEAM_URI` is set | `https://pacsoi-services.faqir.org/hcps/teams/active_patients` |
| `ACTIVE_PATIENTS_POLL_INTERVAL_MS` | Delay between successful polls (default: 60000 ms) | `60000` |
| `TEAM_URI` | Team URI used to scope active-patient discovery | `https://ns.faqir.org/teams/1` |
| `K_ANONYMITY` | Minimum number of distinct patients a distribution, or active patients the population metrics, need before they are served (default: 0) | `5` |
| `LOG_LEVEL` | Set to `debug` to include per-attempt proxy dispatch details | `info` |
| `PATIENT_SOURCE_ADD_INTERVAL_MS` | Pause between adding patients or re-adding suspended groups within one poll (default: 250 ms) | `250` |
| `FETCH_MAX_CONCURRENT_PER_HOST` | Simultaneous request attempts per target host (default: 6) | `6` |
| `FETCH_BREAKER_THRESHOLD` | Consecutive transient failures that pause a host (default: 5) | `5` |
| `FETCH_BREAKER_COOLDOWN_MS` | Pause before a paused host is probed again (default: 30000 ms) | `30000` |
| `FETCH_BASE_DELAY_MS` | First retry delay ceiling, doubled per attempt (default: 1000 ms) | `1000` |
| `FETCH_MAX_DELAY_MS` | Maximum retry delay ceiling (default: 300000 ms) | `300000` |
| `FETCH_SLOW_RETRY_DELAY_MS` | Minimum delay after a client error such as 400 or 404 (default: 60000 ms) | `60000` |
| `FETCH_SOURCE_FAILURE_TIMEOUT_MS` | How long a slice may keep failing before its group is suspended until the next poll (default: 120000 ms) | `120000` |
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
are fetched directly.

### Retries, suspension and load protection

incremunica turns any failed fetch into an error on the shared union query,
which would stop the weight, procedure, or questionnaire projection for every
patient. The fetch adapter in `src/fetch.ts` therefore never fails a pod
request. A request either succeeds, or it ends quietly with an empty result and
tells the source poller what went wrong.

Each patient's eight slices form three groups:

| Group | Slices | Distribution |
| --- | --- | --- |
| `patient` | `PATIENT_SLICE` | identities for both |
| `weight` | `BAR_PROCEDURE_SLICE`, `WEIGHT_SLICE` | `/w-dist` |
| `bariatric` | the five `QUESTIONNAIRE_*_SLICE`s | `/b-dist` |

A group is **suspended** until the next active-patient poll when one of its
slices:

- answers **401 or 403**. This is not retried.
- keeps failing for `FETCH_SOURCE_FAILURE_TIMEOUT_MS` with a network error,
  5xx, 429 or another 4xx. Time spent waiting for a retry or for an open circuit
  breaker counts.
- loses its event stream. A subscription never resumes on its own.

Suspending a group removes its sources and clears that patient's data from the
group's distribution, but keeps the patient's identity. If the patient slice
fails, or both data groups are suspended, the whole patient is suspended
instead, exactly as if they had left the active list. Every successful poll is a
reset point: suspended groups and patients that are still active are added
again from scratch. `GET /population` shows how many groups are in each state.

Revoked access is noticed when a slice next makes a request: a new
subscription, a retry, or the re-add at the next poll. An open event stream that
the pod keeps serving after access is revoked is not checked again, to avoid
extra load on the pod server.

While a group is suspended, that patient is missing from its distribution,
which can bring it under the `K_ANONYMITY` threshold. egress-uma sends event
stream headers at once and a `: keepalive` comment every 30 s on an idle stream,
so idle timeouts on the way (including Node's own 300 s fetch timeouts) do not
close quiet subscriptions. If a stream still gets closed, the group is suspended
until the next poll; the `failed` counts in `/population` make this visible.

Load protection:

- **Retries** use exponential backoff with full jitter, so requests that failed
  together do not retry together. `Retry-After` on 429 and 503 is respected.
  Client errors such as 400 or 404 retry slowly, at least once per
  `FETCH_SLOW_RETRY_DELAY_MS`. Responses without a stream are buffered, so a
  connection that breaks mid-body is retried too.
- **Per-host limits** cap simultaneous attempts per server. Event streams do
  not take a slot, so a quiet subscription never blocks other requests.
- **A per-host circuit breaker** pauses a server after repeated network errors,
  408, 425, 429 or 5xx responses. After the cooldown, a single probe request
  decides whether the others resume.
- **Removed sources** have their pending retries cancelled and their event
  streams closed. With egress-uma, closing the connection also cancels the pod
  request.
- **New patients and re-added groups** are added `PATIENT_SOURCE_ADD_INTERVAL_MS`
  apart, so a poll does not open every source at once.

The active-patient poll itself is not part of any group. It retries
indefinitely, and a failed poll keeps the previous sources.

### Setting the team and k-anonymity through the Aggregator

When deployed through the Aggregator, `TEAM_URI` and `K_ANONYMITY` are not
edited in the manifest. They come from the optional `team` and `k-anonymity`
inputs of the `pacsoi` deployment function
([`config/deployment-functions/pacsoi.yaml`](../../config/deployment-functions/pacsoi.yaml)).
Both inputs can be left out independently:

```http
POST https://aggregator.local:5443/doc-aggregator/services
Content-Type: text/turtle

@prefix aggr: <https://w3id.org/aggregator#> .
@prefix pacsoi: <https://aggregator.local:5443/deployments/pacsoi#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
<https://aggregator.local:5443/doc-aggregator/services/pacsoi>
  a aggr:ServiceRequest ;
  aggr:deploymentFunction <https://aggregator.local:5443/deployments/pacsoi> ;
  pacsoi:team <https://ns.faqir.org/teams/1> ;
  pacsoi:k-anonymity "5"^^xsd:integer .
```

or with the CLI:

```bash
agg create-service \
  --name pacsoi \
  --deployment-function pacsoi \
  --param team=https://ns.faqir.org/teams/1 \
  --param k-anonymity=5
```

See [the PACSOI example](../../docs/pacsoi-example.md) for the full deployment
walkthrough.

## HTTP API

Both endpoints return a point-in-time snapshot under the corresponding mutex.
An empty projection returns only its header row.

When fewer than `K_ANONYMITY` distinct patients contribute to a distribution
(a weight for `/w-dist`, a completed score for `/b-dist`), the endpoint returns
`422 Unprocessable Content` with a JSON body instead of the CSV. `required` is the
configured threshold; the actual patient count is not disclosed:

```json
{"error":"Unprocessable Content","message":"Distribution withheld: fewer than 5 patients contribute","required":5}
```

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

### `GET /population`

Counts without identifiers or health data. `activePatients` is the size of the
last successful active-patient response. When it is below `K_ANONYMITY`, the
endpoint returns `422 Unprocessable Content` instead of the counts, with the
same body as the distributions apart from its message:

```json
{"error":"Unprocessable Content","message":"Population metrics withheld: fewer than 5 patients are active","required":5}
``` For each source group, every active patient is counted once by state:
`ok` (every slice answered), `connecting`, `unauthorized` or `failed` (suspended
until the next poll), or `stopped`. When a patient is suspended because a slice
was unauthorized, all of that patient's groups count as `unauthorized`. `stopped`
is used only for groups cancelled because the whole patient was suspended for
another reason, such as a failed slice or a lost subscription.

```json
{
  "activePatients": 42,
  "lastPoll": { "at": "2026-10-15T12:00:00.000Z", "ok": true },
  "groups": {
    "patient":   { "ok": 40, "connecting": 0, "unauthorized": 1, "failed": 1, "stopped": 0 },
    "weight":    { "ok": 37, "connecting": 1, "unauthorized": 2, "failed": 0, "stopped": 2 },
    "bariatric": { "ok": 35, "connecting": 0, "unauthorized": 4, "failed": 1, "stopped": 2 }
  }
}
```

A failed poll sets `lastPoll.ok` to `false` with an `error` message and keeps the
previous counts.

There is no separate health endpoint. `/population` shows whether the poll
works and how many sources are connected, as long as at least `K_ANONYMITY`
patients are active.

## Code map

| File | Responsibility |
| --- | --- |
| `src/index.ts` | Configuration, lifecycle, mutex ownership, and HTTP routes |
| `src/query.ts` | Incremental query setup, binding validation, source discovery, and group suspension |
| `src/fetch.ts` | UMA proxy fetch, retries, per-host limits and circuit breaker, per-source scopes and outcome reports |
| `src/population.ts` | Active-patient and per-group status counts served by `/population` |
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
   `unauthorized` and `gave-up` mark a source being suspended, `stream-ended` a
   lost subscription, and `cancelled` a request ended because its source was
   removed. `[FETCH gate] breaker-open` and `breaker-closed` show when a host is
   paused. `[querySources] Suspending ...` names the group or patient and why;
   `GET /population` summarizes the current states.
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
- Slice requests never fail towards the query engines; failing ones are
  suspended per group instead (see "Retries, suspension and load protection").
  The active-patient poll retries indefinitely.
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
