# Defining deployable services

The platform deploys workloads described by Kubernetes custom resources. A
`DeploymentFunction` is required; a `Profile` is optional.

- `DeploymentFunction` declares the public deployment function, Kubernetes
  resources, input bindings, and route bindings.
- `Profile` adds a reusable semantic interface: service parameters, functions,
  endpoints, datasets, and distributions.

The Aggregator Server watches these resources and publishes them at
`/deployments` and `/profiles`. Aggregator instances never read the CRDs
directly.

## Start from a working definition

The repository contains runnable examples:

- `config/deployment-functions/fetch-profiled.yaml`
- `config/deployment-functions/fetch-unprofiled.yaml`
- `config/profiles/fetch.yaml`
- `config/deployment-functions/pacsoi.yaml`
- `config/profiles/pacsoi.yaml`

The Makefile automatically adds every YAML file in
`config/deployment-functions/` and `config/profiles/` to Helm deployments. To
add a service type:

1. Build or otherwise publish its container image.
2. Add a `DeploymentFunction` entry under `deploymentFunctions` in a values
   file in `config/deployment-functions/`.
3. If the service has a reusable semantic interface, add a `Profile` under
   `profiles` in `config/profiles/` and reference it with `profileRef.name`.
4. Run `make deploy`, `make kind-deploy`, or `make slices-deploy`.
5. Inspect `GET /deployments/{name}` before creating a service instance.

For local images, build and load one container with:

```bash
make containers-all CONTAINER=<directory-under-containers>
```

## Definition rules

Important validation rules enforced by the CRDs and catalog compiler include:

- embedded manifests omit `metadata.name` and `metadata.namespace`; the
  platform assigns both;
- orchestration resource IDs and container names are local references;
- ConfigMap and PersistentVolumeClaim references inside Deployment manifests
  use the corresponding orchestration resource ID (for example, a PVC with
  `id: storage` is referenced as `claimName: storage`), not a fixed Kubernetes
  name;
- input bindings target an environment variable in a specific resource and
  container;
- route bindings target a named container port, not a numeric port;
- a deployment uses either `profileRef` or an inline `interface`, never both;
- every declared public endpoint or distribution has a corresponding route
  binding; and
- a profiled output references an existing dataset profile.

The complete schema, profiled example, routing model, identifier rules, and
internal bundle contract are in [Deployment definitions and
profiles](deployment-definitions.md). The authoritative structural schemas are
the CRDs in `aggregator-platform/crds/`.

## Deploy an instance

Definitions describe service types; users instantiate them by posting an RDF
`aggr:ServiceRequest` to an aggregator's `/services` collection. See
[Deploying services](deploying-services.md).
