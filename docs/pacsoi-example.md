# PACSOI example

This example deploys the PACSOI service in `containers/pacsoi-service`. The
service watches patient weight and procedure slices and exposes a monthly weight
distribution as CSV.

## Prerequisites

You need:

- a running Aggregator Platform with the PACSOI definition files enabled;
- a Kvasir Solid Server (KSS) and UMA server configured as described in
  [KSS setup](kss-setup.md);
- a doctor pod containing a slice that lists patient pod URLs; and
- patient pods containing weight-observation and procedure slices.

The example below uses:

| Setting | Value |
| --- | --- |
| Aggregator host | `https://aggregator.local:5443` |
| FAQIR management ID | `hospital-1` |
| Generated source slice | `https://pacsoi-kvasir.faqir.org/faqir-management/slices/hospital-1-ActivePatients/query` |
| Patient slice name | `PatientSlice` |
| Weight slice name | `WeightObservationsSlice` |
| Oxford slice name | `OxfordResponseSlice` |
| Bariatric Procedure slice name | `BariatricProcedureSlice` |
| Knee Procedure slice name | `KneeProcedureSlice` |

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
`WEIGHT_SLICE`, `OXFORD_SLICE`, `BAR_PROCEDURE_SLICE`, and
`KNEE_PROCEDURE_SLICE` values in
[`config/deployment-functions/pacsoi.yaml`](../config/deployment-functions/pacsoi.yaml),
under `orchestration.resources[].manifest.spec.template.spec.containers[].env`.

The same file constructs `SOURCES` from the service's `id` input. To use a
different Kvasir host, path, or slice naming convention, change the
`valueTemplate` on the `SOURCES` input binding:

```yaml
inputBindings:
  - parameter: id
    targets:
      - resource: workload
        container: pacsoi
        env: SOURCES
        valueTemplate: https://pacsoi-kvasir.faqir.org/faqir-management/slices/{{value}}-ActivePatients/query
```

At deployment time, every `{{value}}` placeholder is replaced with the supplied
`id`. For example, `hospital-1` produces
`https://pacsoi-kvasir.faqir.org/faqir-management/slices/hospital-1-ActivePatients/query`.

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
@prefix pacsoi: <https://aggregator.local:5443/deployments/pacsoi#> .

<https://aggregator.local:5443/doc-aggregator/services/pacsoi>
  a aggr:ServiceRequest ;
  aggr:deploymentFunction <https://aggregator.local:5443/deployments/pacsoi> ;
  pacsoi:id "hospital-1" .
```

The equivalent CLI command is:

```bash
agg create-service \
  --name pacsoi \
  --deployment-function pacsoi \
  --param id=hospital-1
```

## Retrieve the result

Inspect the service description and follow its advertised
`dcat:downloadURL`:

```http
GET https://aggregator.local:5443/doc-aggregator/services/pacsoi
Accept: text/turtle
```

The output enpoints will be at:
- `https://aggregator.local:5443/doc-aggregator/services/pacsoi/w-dist` for the weight distribution; and
- `https://aggregator.local:5443/doc-aggregator/services/pacsoi/o-dist` for the oxford distribution.

With the CLI, discover and fetch the distribution without constructing its URL:

```bash
agg list-outputs --svc pacsoi
agg get-output weight-distribution/csv --svc pacsoi
```
