# Deployment definitions and profiles

The Aggregator Server owns the platform-wide deployment definitions through two
namespaced custom resources:

- `DeploymentFunction` describes one deployable function and all Kubernetes,
  input, and routing details needed to instantiate it.
- `Profile` describes the optional semantic service interface and reusable
  dataset profiles.

Both resources live in the same namespace as the Aggregator Platform. Deployed
aggregator instances do not read these CRDs. The server watches them, validates
and compiles them once, and supplies an atomic bundle to an instance over a
cluster-only endpoint.

## Published identifiers

The Aggregator Server publishes two RDF catalogs:

| Resource | Public URL |
| --- | --- |
| Profile catalog | `/profiles` |
| Profile | `/profiles/{name}` |
| Deployment catalog | `/deployments` |
| Deployment function | `/deployments/{name}` |

Terms declared by a document use fragments of that document. For example, the
`url` input of the `fetch-profiled` deployment is
`https://aggregator.example/deployments/fetch-profiled#url`. A dataset in the `fetch`
profile is `https://aggregator.example/profiles/fetch#dataset-fetched-content`.

A deployment function always has one output whose FnO type is
`aggr:Service`. When `profileRef` is present, that output uses
`dct:conformsTo` to reference `/profiles/{profile-name}`. An unprofiled
deployment has no such triple.

## Mapping public paths to workloads

Profiles describe semantics and public paths; deployment functions describe
where those paths run. `routeBindings` joins the two by their local keys:

```text
Profile endpoint/distribution key
        -> DeploymentFunction route binding
        -> resource id
        -> container name
        -> named container port + optional internal path
```

For a distribution named `content` in dataset `fetched-content`, this looks
like:

```yaml
routeBindings:
  distributions:
    fetched-content:
      content:
        resource: workload
        container: fetch
        port: http
        internalPath: /
```

`resource` refers to an entry in `orchestration.resources`, `container` refers
to a container in that resource's Deployment manifest, and `port` is the
container port name rather than a number. The platform assigns Kubernetes
resource names and namespaces. Therefore embedded manifests must omit
`metadata.name` and `metadata.namespace`.

Operational endpoints (`executes` and `updates`) and dataset distributions are
separate concepts. A GET operation that only executes or updates a function is
not automatically exposed as a dataset. Every function output exposed as a
dataset must reference a `DatasetProfile`, and every distribution in that
profile must have a route binding.

## Profiled fetch example

The profile is optional, but a profiled fetch deployment can reference this
server-wide definition:

```yaml
apiVersion: aggregator.example.org/v1alpha1
kind: Profile
metadata:
  name: fetch
spec:
  serviceProfile:
    title: Fetch service
    parameters:
      source:
        predicate: source
        type: xsd:anyURI
        required: true
    outputs:
      content:
        predicate: content
        datasetProfileRef:
          dataset: fetched-content
    functions:
      fetch:
        expects: [source]
        returns: [content]
  datasetProfiles:
    fetched-content:
      title: Fetched content
      distributions:
        content:
          path: /content
          urlType: accessURL
```

```yaml
apiVersion: aggregator.example.org/v1alpha1
kind: DeploymentFunction
metadata:
  name: fetch-profiled
spec:
  function:
    title: Deploy fetch service
    expects:
      - name: url
        predicate: url
        type: xsd:anyURI
        required: true
    returns:
      name: deployedService
      predicate: service
  profileRef:
    name: fetch
  orchestration:
    resources:
      - id: workload
        manifest:
          apiVersion: apps/v1
          kind: Deployment
          spec:
            template:
              spec:
                containers:
                  - name: fetch
                    image: example/fetch:latest
                    ports:
                      - name: http
                        containerPort: 8080
    inputBindings:
      - parameter: url
        targets:
          - resource: workload
            container: fetch
            env: GET_URL
    routeBindings:
      distributions:
        fetched-content:
          content:
            resource: workload
            container: fetch
            port: http
            internalPath: /
```

For an unprofiled version, omit `profileRef` and provide the public datasets or
endpoints under `spec.interface`. The orchestration and binding model remains
the same, so both forms follow one deployment path.

## Internal bundle API

Aggregator instances resolve a selected deployment by calling:

```http
GET http://aggregator-server-svc:5001/internal/deployment-functions/{name}
```

Port `5001` is exposed by the cluster `Service` but is not routed by the public
Ingress. A successful response is a versioned JSON envelope containing the
complete `DeploymentFunction` and, when referenced, its resolved `Profile`:

```json
{
  "apiVersion": "aggregator.example.org/v1alpha1",
  "kind": "DeploymentBundle",
  "deploymentFunction": {},
  "profile": {}
}
```

The response has an `ETag` and `Cache-Control: no-cache`. Instances may retain
the last valid bundle and revalidate it with `If-None-Match`; unchanged content
returns `304 Not Modified`. The registry swaps a newly validated snapshot in
one operation, so a bundle never combines a new deployment with an old profile.

The endpoint returns `404` for unknown names and `405` for methods other than
GET or HEAD. It is an internal API: do not expose port `5001` through an
Ingress or external Service.

## Instance consumption

A service request selects the public deployment document, for example:

```turtle
<https://aggregator.example/my-aggregator/services/fetch-1> a aggr:ServiceRequest ;
  aggr:deploymentFunction <https://aggregator.example/deployments/fetch-profiled> ;
  <https://aggregator.example/deployments/fetch-profiled#url> <https://example.org/data> .
```

The aggregator instance extracts `fetch-profiled`, fetches its bundle from the
internal API, and binds the request predicate to the declared environment
target. It does not read `Profile` or `DeploymentFunction` CRDs and receives no
RBAC permission to do so.

The instance resolves the bundle into its runtime model. It creates `ConfigMap`
and `PersistentVolumeClaim` resources before `Deployment` resources, injects
inputs directly into the selected container environment fields, and creates a
Kubernetes Service per routed workload.
Multiple distributions and operational endpoints may therefore target
different resources and named ports.

Within a Deployment manifest, ConfigMap and PVC resource IDs are local symbolic
names in standard PodSpec reference fields. For example, `configMap.name:
settings` references the orchestration resource with `id: settings`; the
instance replaces it with that service instance's generated Kubernetes name.
This applies to ConfigMap volumes, PVC volumes, `envFrom.configMapRef`, and
`env.valueFrom.configMapKeyRef`.

Generated RDF service descriptions continue to use `rdfgo`. A profiled service
uses `dct:conformsTo` to reference its `/profiles/{name}` document, and each
dataset references its dataset-profile fragment. Unprofiled services do not
emit a `dct:conformsTo` statement.

## Helm values

The chart can create definitions from values:

```yaml
profiles:
  fetch:
    # Profile spec (the contents below `spec` above)

deploymentFunctions:
  fetch:
    # DeploymentFunction spec (the contents below `spec` above)
```

The server watches the resulting CRDs. Editing a resource causes a background
recompile; HTTP requests continue to use the previous valid snapshot until the
complete new snapshot validates.

Runnable Helm-value fixtures are included for the fetch examples:

- `config/profiles/fetch.yaml`
- `config/deployment-functions/fetch-profiled.yaml`
- `config/deployment-functions/fetch-unprofiled.yaml`

The PACSOI service has a complete profiled definition:

- `config/profiles/pacsoi.yaml`
- `config/deployment-functions/pacsoi.yaml`

They can be added to the normal platform values with additional `-f` flags.
The Makefile adds all files in these definition directories automatically. The
profiled and unprofiled fetch deployment names are deliberately different so
both catalog documents can be inspected in one installation.
