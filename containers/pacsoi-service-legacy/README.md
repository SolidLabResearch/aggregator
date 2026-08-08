# PACSOI service — legacy fallback

This standalone container preserves the PACSOI implementation from commit
`25598a3` (`deployment config`). It predates patient-slice identifier resolution,
out-of-order procedure buffering, and active-patient removal.

Use it only as an operational fallback. New development belongs in
`containers/pacsoi-service`.

## Behavioral differences

The legacy implementation:

- does not query a patient-details slice or require `PATIENT_SLICE`;
- uses identifiers from procedure, weight, and Oxford bindings directly;
- does not remove aggregate contributions when an HCP source is deleted;
- uses one mutex for both output projections; and
- retains the older procedure and pre-procedure buffering behavior.

Its HTTP API remains compatible: `GET /w-dist` and `GET /o-dist` return the same
CSV column layouts as the current implementation.

## Build

From the repository root:

```bash
make containers-all CONTAINER=pacsoi-service-legacy
```

Or build it directly:

```bash
docker build \
  -t pacsoi-service-legacy:latest \
  containers/pacsoi-service-legacy
```

For a local compilation check:

```bash
cd containers/pacsoi-service-legacy
npm ci
npm run build
```

## Deploy through the Aggregator Platform

The legacy definitions are independent from the current service:

- `config/deployment-functions/pacsoi-legacy.yaml`
- `config/profiles/pacsoi-legacy.yaml`

Create a service with the deployment function `pacsoi-legacy`. It accepts the
five legacy inputs and intentionally has no `patient-slice` input.

```bash
agg create-service \
  --name pacsoi-fallback \
  --deployment-function pacsoi-legacy \
  --param sources=http://localhost:8080/doctor/PatientSlice \
  --param weight-slice=WeightObservationsSlice \
  --param oxford-slice=OxfordResponseSlice \
  --param bar-procedure-slice=BariatricProcedureSlice \
  --param knee-procedure-slice=KneeProcedureSlice
```

## Run the image directly

```bash
docker run --rm -p 3000:3000 \
  -e SOURCES=http://host.docker.internal:8080/doctor/PatientSlice/query \
  -e BAR_PROCEDURE_SLICE=BariatricProcedureSlice \
  -e KNEE_PROCEDURE_SLICE=KneeProcedureSlice \
  -e WEIGHT_SLICE=WeightObservationsSlice \
  -e OXFORD_SLICE=OxfordResponseSlice \
  pacsoi-service-legacy:latest
```

Keep the current and legacy image tags distinct so fallback behavior never
depends on a mutable image shared by both implementations.
