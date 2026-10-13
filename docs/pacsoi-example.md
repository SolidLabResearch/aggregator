# PACSOI example

This example deploys the PACSOI service in `containers/pacsoi-service`. The
service watches patient weight, procedure, and bariatric questionnaire slices.
It exposes weight and OWLQOL/WRSM score distributions as CSV.

## Prerequisites

You need:

- a running Aggregator Platform with the PACSOI definition files enabled;
- a Kvasir Solid Server (KSS) and UMA server configured as described in
  [KSS setup](kss-setup.md);
- access through the egress proxy to the HCP active-patients API; and
- patient pods containing weight-observation, procedure, and bariatric
  questionnaire slices.

The example below uses:

| Setting | Value |
| --- | --- |
| Aggregator host | `https://aggregator.local:5443` |
| Active-patients endpoint | `https://pacsoi-services.faqir.org/hcps/active_patients` |
| Active-patients poll interval | `60000` ms |
| Kvasir pod base URL | `https://pacsoi-kvasir.faqir.org` |
| Patient slice name | `PatientSlice` |
| Weight slice name | `WeightObservationsSlice` |
| Bariatric Procedure slice name | `BariatricProcedureSlice` |
| Preoperative questionnaire slice | `PreopBariatricResponseSlice` |
| 6-week questionnaire slice | `Postop6wBariatricResponseSlice` |
| 3-month questionnaire slice | `Postop3mBariatricResponseSlice` |
| 6-month questionnaire slice | `Postop6mBariatricResponseSlice` |
| 1-year questionnaire slice | `Postop1yBariatricResponseSlice` |

The Aggregator's egress UMA proxy must be authorized to read the source and
patient slices.

## Install the definitions

The PACSOI configuration consists of:

- `config/profiles/pacsoi.yaml`, which describes the service and its CSV
  dataset distribution; and
- `config/deployment-functions/pacsoi.yaml`, which describes the workload,
  inputs, environment bindings, and route binding.

The slice names are deployment settings rather than service input parameters.
If your Kvasir deployment uses different names, change the `PATIENT_SLICE`,
`WEIGHT_SLICE`, `BAR_PROCEDURE_SLICE`, and the five `QUESTIONNAIRE_*_SLICE`
values in
[`config/deployment-functions/pacsoi.yaml`](../config/deployment-functions/pacsoi.yaml),
under `orchestration.resources[].manifest.spec.template.spec.containers[].env`.

The same file configures the active-patients API and polling interval. Change
these environment values to use another endpoint or interval:

```yaml
env:
  - name: ACTIVE_PATIENTS_URL
    value: "https://pacsoi-services.faqir.org/hcps/active_patients"
  - name: TEAM_ACTIVE_PATIENTS_URL
    value: "https://pacsoi-services.faqir.org/hcps/teams/active_patients"
  - name: ACTIVE_PATIENTS_POLL_INTERVAL_MS
    value: "60000"
  - name: POD_BASE_URL
    value: "https://pacsoi-kvasir.faqir.org"
```

The endpoint must return a JSON array containing a non-empty `id` and `pod_id`
for every active patient. Relative pod identifiers are resolved below
`POD_BASE_URL`; absolute pod URLs remain supported. Authorization is handled by
the egress proxy in OAuth mode.

The deployment function also accepts two optional inputs, which are set per
service request (see [Deploy PACSOI](#deploy-pacsoi)):

- `team`: when supplied, the service fetches pods from
  `TEAM_ACTIVE_PATIENTS_URL` and sends the URL-encoded URI in its `team_uri`
  query parameter.
- `k-anonymity`: the minimum number of distinct patients a distribution needs
  before it is served (default `0`). Below that threshold the distribution
  endpoint returns `403 Forbidden` instead of the CSV.

### Update contexts, slice definitions, and queries

The data model used to read each slice is defined in
[`containers/pacsoi-service/src/schemas.ts`](../containers/pacsoi-service/src/schemas.ts).
For each slice, that file keeps three related definitions together:

- the `*_SLICE_CONTEXT` maps compact names and prefixes to RDF IRIs;
- the `*_SLICE_SCHEMA` describes the GraphQL-LD types, fields, filters, and
  subscription exposed by the slice; and
- the `*_QUERY` SPARQL query selects the data consumed by the PACSOI service.

Use this map to find the definitions to update:

| Slice | JSON-LD context | GraphQL-LD slice schema | SPARQL query |
| --- | --- | --- | --- |
| Patient details | `PATIENT_SLICE_CONTEXT` | `PATIENT_SLICE_SCHEMA` | `PATIENT_QUERY` |
| Weight values | `WEIGHT_SLICE_CONTEXT` | `WEIGHT_SLICE_SCHEMA` | `WEIGHT_QUERY` |
| Bariatric procedures | `BAR_PROCEDURE_SLICE_CONTEXT` | `BAR_PROCEDURE_SLICE_SCHEMA` | `PROCEDURE_QUERY` |
| Bariatric questionnaire responses | `QUESTIONNAIRE_SLICE_CONTEXT` | five `QUESTIONNAIRE_*_SLICE_SCHEMA` definitions | `QUESTIONNAIRE_QUERY` |

When changing a slice model, keep all three layers aligned:

1. Update its context if a prefix or RDF predicate/class IRI changes.
2. Update its slice schema if the query root, RDF types, relationships, fields,
   filters, or subscription shape changes.
3. Update its SPARQL query to match the new RDF model. The `SELECT` variable
   names are consumed directly by
   [`containers/pacsoi-service/src/query.ts`](../containers/pacsoi-service/src/query.ts),
   so preserve those binding names or update `query.ts` at the same time.

`QUESTIONNAIRE_QUERY` is shared by all five follow-up slices. The questionnaire
URI in each binding assigns the response to its follow-up point.

The standard deployment commands load both files automatically:

```bash
make containers-all CONTAINER=pacsoi-service
make kind-deploy
```

Confirm that the public documents are available:

```http
GET https://aggregator.local:5443/profiles/pacsoi
Accept: text/turtle

GET https://aggregator.local:5443/deployments/pacsoi
Accept: text/turtle
```

## Register the doctor's aggregator

Start device-code registration:

```http
POST https://aggregator.local:5443/registration
Content-Type: application/json

{
  "registration_type": "device_code",
  "authorization_server": "http://localhost:4000/uma"
}
```

Open the returned `verification_uri_complete` and authenticate as the doctor.
Poll the same endpoint with the returned state until registration completes:

```http
POST https://aggregator.local:5443/registration
Content-Type: application/json

{
  "registration_type": "device_code",
  "state": "<state>"
}
```

The successful response contains the aggregator URL. The remaining examples
use `https://aggregator.local:5443/doc-aggregator`.

## Deploy PACSOI

Create a service through the aggregator's service collection. The predicates
come from the published PACSOI deployment document.

```http
POST https://aggregator.local:5443/doc-aggregator/services
Content-Type: text/turtle

@prefix aggr: <https://w3id.org/aggregator#> .
<https://aggregator.local:5443/doc-aggregator/services/pacsoi>
  a aggr:ServiceRequest ;
  aggr:deploymentFunction <https://aggregator.local:5443/deployments/pacsoi> .
```

The equivalent CLI command is:

```bash
agg create-service \
  --name pacsoi \
  --deployment-function pacsoi
```

### Optional: scope to a team and set k-anonymity

Add the optional inputs as extra triples on the request. Each predicate is the
deployment document IRI followed by `#` and the input's predicate name. This
request limits patient discovery to team `https://ns.faqir.org/teams/1` and
withholds each distribution until at least 5 patients contribute to it:

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

The equivalent CLI command is:

```bash
agg create-service \
  --name pacsoi \
  --deployment-function pacsoi \
  --param team=https://ns.faqir.org/teams/1 \
  --param k-anonymity=5
```

Either input can be left out independently. Without `team`, all active
patients from `ACTIVE_PATIENTS_URL` are used; without `k-anonymity`, the
distributions are served regardless of patient count.

## Retrieve the result

Inspect the service description and follow its advertised
`dcat:downloadURL`:

```http
GET https://aggregator.local:5443/doc-aggregator/services/pacsoi
Accept: text/turtle
```

The output enpoints will be at:
- `https://aggregator.local:5443/doc-aggregator/services/pacsoi/w-dist` for the weight distribution; and
- `https://aggregator.local:5443/doc-aggregator/services/pacsoi/b-dist` for the bariatric questionnaire score distribution.

With the CLI, discover and fetch the distribution without constructing its URL:

```bash
agg list-outputs --svc pacsoi
agg get-output weight-distribution/csv --svc pacsoi
agg get-output bariatric-score-distribution/csv --svc pacsoi
```

If the service was created with `k-anonymity` and too few patients contribute
to a distribution, its endpoint returns `403 Forbidden` with a JSON body such
as:

```json
{"error":"Forbidden","message":"Distribution withheld: fewer than 5 patients contribute (k-anonymity)","kAnonymity":5}
```

The distribution becomes available automatically once enough patient data has
been received.
