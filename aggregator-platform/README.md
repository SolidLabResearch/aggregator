# Aggregator Platform Helm chart

This document describes the structure of the Helm templates and custom resource
definitions in this chart.

## Chart structure

```text
aggregator-platform/
├── Chart.yaml
├── values.yaml
├── values.schema.json
├── crds/
│   ├── fno-description.yaml
│   └── service-configuration.yaml
└── templates/
    ├── NOTES.txt
    ├── _helpers.tpl
    ├── egress-serivce-account.yaml
    ├── fno-descriptions.yaml
    ├── ingress-uma-deployment.yaml
    ├── ingress-uma-service.yaml
    ├── instance-service-account.yaml
    ├── server-config.yaml
    ├── server-deployment.yaml
    ├── server-ingress.yaml
    ├── server-secrets.yaml
    ├── server-service-account.yaml
    ├── server-service.yaml
    ├── service-configurations.yaml
    ├── spec-config.yaml
    ├── tokens-deployment.yaml
    ├── tokens-service-account.yaml
    └── tokens-service.yaml
```

The chart uses fixed resource names. Resources are created in the Helm release
namespace unless Kubernetes requires them to be cluster-scoped.

## Template helpers

### `_helpers.tpl`

Defines two shared helpers:

- `aggregator.labels` adds the application name, platform name, Helm release,
  chart application version, and Helm management labels.
- `aggregator.annotations` adds the Helm release name and namespace
  annotations.

The common application label is `aggregator-server`. Workload templates add an
`app.kubernetes.io/component` label to distinguish the server, Ingress-UMA, and
Token Service.

### `NOTES.txt`

Produces the post-render release notes. It derives the platform,
deployment-catalog, and registration URLs from:

- `external.host`;
- `tls.enabled`;
- `spec.deployment_catalog`; and
- `spec.registration`.

## Aggregator Server templates

### `server-config.yaml`

Creates the `server-config` ConfigMap. It supplies runtime configuration to the
Aggregator Server:

| ConfigMap key | Helm value or release field |
| --- | --- |
| `NAMESPACE` | `.Release.Namespace` |
| `LOG_LEVEL` | `loglevel` |
| `EXTERNAL_HOST` | `external.host` |
| `EXTERNAL_HTTP_PORT` | `external.httpPort` |
| `EXTERNAL_HTTPS_PORT` | `external.httpsPort` |
| `ALLOWED_REGISTRATION_TYPES` | comma-separated `auth.allowedRegistrationTypes` |
| `SOLID_OIDC` | `auth.solidOidc` |
| `OIDC_CLIENT_ID` | `auth.oidc.clientId` |
| `OIDC_SERVER` | `auth.oidc.server` |
| `PROVISION_CLIENT_ID` | `auth.provision.clientId` |
| `PROVISION_CLIENT_SECRET` | `auth.provision.clientSecret` |
| `PROVISION_WEBID` | `auth.provision.webId` |
| `PROVISION_AUTHORIZATION_SERVER` | `auth.provision.authServer` |
| `CLIENT_CRED_ID` | `auth.client_credentials.clientId` |
| `AGGREGATOR_IMAGE` | `aggregator.image.repository` |
| `AGGREGATOR_TAG` | `aggregator.image.tag` |
| `AGGREGATOR_PULL_POLICY` | `aggregator.image.pullPolicy` |
| `EGRESS-UMA_IMAGE` | `egressUma.image.repository` |
| `EGRESS-UMA_TAG` | `egressUma.image.tag` |
| `EGRESS-UMA_PULL_POLICY` | `egressUma.image.pullPolicy` |
| `INGRESS_CLASS_NAME` | `ingressClassName` |
| `TLS_SECRET` | `tls.secretName`, only when TLS is enabled |

All ConfigMap values render as strings. Missing optional authentication values
render as empty strings.

### `spec-config.yaml`

Creates the `spec-config` ConfigMap:

| ConfigMap key | Helm value |
| --- | --- |
| `DEPLOYMENT_CATALOG` | `spec.deployment_catalog` |
| `SERVICE_COLLECTION` | `spec.service_collection` |
| `REGISTRATION` | `spec.registration` |

### `server-deployment.yaml`

Creates the `aggregator-server` Deployment.

- Replicas come from `server.replicaCount`.
- The container image is assembled from `server.image.repository` and
  `server.image.tag`.
- The container listens on port `5000`.
- Environment variables are loaded from `server-config` and `spec-config`.
- The pod uses the `aggregator-server-sa` service account.
- Readiness is checked at `GET /healthz` on port `5000`.
- Probe timing and thresholds come from `server.readinessProbe`.
- When either `auth.oidc.clientSecret` or
  `auth.client_credentials.clientSecret` exists, the
  `aggregator-server-secret` Secret is mounted read-only at `/etc/secrets`.

### `server-service.yaml`

Creates the `aggregator-server-svc` ClusterIP Service. It selects the server
component and maps Service port `5000` to container port `5000`.

### `server-ingress.yaml`

Creates the `aggregator-server-ingress` Ingress.

- `ingressClassName` selects the Ingress controller.
- `external.host` becomes the single host rule.
- The `/` prefix routes to `aggregator-server-svc` on port `5000`.
- When `tls.enabled` is true, the Ingress references `tls.secretName` for
  `external.host`.

### `server-secrets.yaml`

This template conditionally creates authentication and TLS resources.

When an OIDC or client-credentials secret is configured, it creates the
`aggregator-server-secret` Opaque Secret:

| Secret key | Helm value |
| --- | --- |
| `oidcSecret` | `auth.oidc.clientSecret` |
| `credSecret` | `auth.client_credentials.clientSecret` |

When experimental self-signed TLS is enabled, it creates a
`kubernetes.io/tls` Secret named by `tls.secretName`.

When experimental cert-manager TLS is enabled, it creates a cert-manager
`Certificate`. Its DNS names, issuer reference, duration, and renewal window
come from `tls.certManager`.

TLS support is under development. The TLS template structure and values may
change.

### `server-service-account.yaml`

Creates the `aggregator-server-sa` ServiceAccount and two sets of namespaced
RBAC rules.

The `aggregator-instance-manager` Role allows the server to manage:

- Pods, Services, and ConfigMaps;
- Deployments;
- Ingresses;
- Secrets;
- ServiceAccounts; and
- Roles and RoleBindings.

The matching `aggregator-instance-manager-binding` RoleBinding assigns the Role
to `aggregator-server-sa`.

The `aggregator-cr-reader` Role grants read-only access to `FnoDescription` and
`ServiceConfiguration` resources. The
`aggregator-cr-reader-binding` RoleBinding assigns it to
`aggregator-server-sa`.

## Ingress-UMA templates

### `ingress-uma-deployment.yaml`

Creates the `ingress-uma` Deployment.

- Replicas come from `ingressUma.replicaCount`.
- The image is assembled from `ingressUma.image.repository` and
  `ingressUma.image.tag`.
- The container listens on port `8080`.
- `EXTERNAL_HOST` receives `external.host`.
- `DISABLE_AUTH` receives `ingressUma.disableAuth`.
- Readiness is checked at `GET /healthz` on port `8080`.
- Probe settings come from `ingressUma.readinessProbe`.
- Pod shutdown grace comes from
  `ingressUma.terminationGracePeriodSeconds`.

### `ingress-uma-service.yaml`

Creates the `ingress-uma` ClusterIP Service. It selects the Ingress-UMA
component and maps Service port `8080` to container port `8080`.

## Token Service templates

### `tokens-deployment.yaml`

Creates the `token-service` Deployment.

- Replicas come from `tokenService.replicaCount`.
- The image is assembled from `tokenService.image.repository` and
  `tokenService.image.tag`.
- The container listens on port `8080`.
- `LOG_LEVEL` receives `loglevel`.
- `NAMESPACE` receives the Helm release namespace.
- The pod uses the `token-service-sa` service account.
- Readiness is checked at `GET /healthz` on port `8080`.
- Probe settings come from `tokenService.readinessProbe`.
- Pod shutdown grace comes from
  `tokenService.terminationGracePeriodSeconds`.

### `tokens-service.yaml`

Creates the `token-service` ClusterIP Service. It selects the Token Service
component and maps Service port `8080` to container port `8080`.

### `tokens-service-account.yaml`

Creates:

- the `token-service-sa` ServiceAccount;
- the `token-service-role` Role; and
- the `token-service-binding` RoleBinding.

The Role grants read access to Pods and read, update, patch, and delete access
to Secrets in the release namespace.

## Dynamically created instance support

### `instance-service-account.yaml`

Creates the namespaced `aggregator-service-manager` Role. It grants management
permissions for Deployments and Services.

The chart does not create a RoleBinding for this Role. When the platform creates
an aggregator instance, it binds the Role to that instance's service account.

### `egress-serivce-account.yaml`

Creates:

- the `egress-uma-sa` ServiceAccount;
- the `egress-uma-configmap-editor` Role; and
- the `egress-uma-configmap-binding` RoleBinding.

The Role permits Egress-UMA to get, list, create, update, and patch ConfigMaps
in the release namespace.

## Custom resource templates

### `fno-descriptions.yaml`

Iterates over the `fnoDescriptions` values map and creates one
`aggregator.example.org/v1alpha1` `FnoDescription` per entry.

The map key becomes `metadata.name`. Each resource contains:

```yaml
apiVersion: aggregator.example.org/v1alpha1
kind: FnoDescription
metadata:
  name: <map key>
  namespace: <release namespace>
  labels:
    aggregator.example.org/fno-type: <type>
spec:
  type: <deployment-function or implementation>
  serviceConfigurationRef:
    name: <referenced configuration>
    namespace: <optional namespace>
  description: |
    <FnO RDF in Turtle syntax>
```

`serviceConfigurationRef` is emitted only when configured. Its `namespace`
field is also optional.

### `service-configurations.yaml`

Iterates over the `serviceConfigurations` values map and creates one
`aggregator.example.org/v1alpha1` `ServiceConfiguration` per entry.

The map key becomes `metadata.name`. The template conditionally emits
`prefixes`, `inputMapping`, and `datasets`; it always emits
`serviceMapping`:

```yaml
apiVersion: aggregator.example.org/v1alpha1
kind: ServiceConfiguration
metadata:
  name: <map key>
  namespace: <release namespace>
spec:
  prefixes: {}
  inputMapping: {}
  datasets: {}
  serviceMapping: {}
```

## Custom resource definitions

CRDs are stored in `crds/`, so Helm processes them before the resources in
`templates/`. Both CRDs are cluster-scoped definitions for namespaced custom
resources in API group `aggregator.example.org` and version `v1alpha1`.

### `FnoDescription`

Resource identity:

| Field | Value |
| --- | --- |
| Kind | `FnoDescription` |
| Plural | `fnodescriptions` |
| Singular | `fnodescription` |
| Short name | `fno` |
| Scope | Namespaced |

Schema:

| Field | Type | Required | Constraints and purpose |
| --- | --- | --- | --- |
| `spec.type` | string | yes | `deployment-function` or `implementation` |
| `spec.description` | string | yes | RDF description represented as Turtle |
| `spec.serviceConfigurationRef` | object | no | Reference to a service configuration |
| `spec.serviceConfigurationRef.name` | string | when the reference exists | Referenced resource name |
| `spec.serviceConfigurationRef.namespace` | string | no | Optional reference namespace |

### `ServiceConfiguration`

Resource identity:

| Field | Value |
| --- | --- |
| Kind | `ServiceConfiguration` |
| Plural | `serviceconfigurations` |
| Singular | `serviceconfiguration` |
| Short name | `svcconf` |
| Scope | Namespaced |

Its schema connects FnO parameters and outputs to a Kubernetes workload.

#### Prefixes

`spec.prefixes` is a string map of RDF prefix names to URI values. Application
defaults include `dct`, `dcat`, `foaf`, `skos`, `schema`, `fno`, and `xsd`.
User-defined entries override defaults.

#### Input mapping

`spec.inputMapping` maps FnO parameter predicates to input definitions:

```yaml
inputMapping:
  <predicate>:
    id: <substitution identifier>
```

`id` is required. The runtime substitutes occurrences of `$(id)` in the
orchestration object.

#### Datasets

`spec.datasets` describes the datasets exposed by the deployed service. Map
keys are local dataset identifiers; they are not FnO output predicates.

Each dataset may define:

- `title`;
- `description`;
- `extraProperties`;
- `distribution.title`;
- `distribution.description`;
- `distribution.extraProperties`; and
- `distribution.access`.

A `dcat:Dataset` is generated for every entry. A `dcat:Distribution` is
generated only when `distribution` exists.

`distribution.access` contains:

| Field | Type | Required | Constraints and purpose |
| --- | --- | --- | --- |
| `urlType` | string | yes | `accessURL` or `downloadURL` |
| `servicePort` | integer | yes | Port exposed by the generated Service |
| `internalPath` | string | no | Path on the internal workload |
| `externalPath` | string | no | Path exposed by the aggregator |
| `protocol` | string | no | `http` or `https`; schema default is `http` |

#### Service mapping

`spec.serviceMapping` is required and contains optional DataService metadata and
required orchestration configuration.

`spec.serviceMapping.dataservice` may contain:

- `title`;
- `description`; and
- `extraProperties`.

`spec.serviceMapping.orchestration` contains:

| Field | Type | Required | Constraints and purpose |
| --- | --- | --- | --- |
| `type` | string | yes | `Deployment`, `Job`, or `CronJob` |
| `trigger` | object | no | HTTP trigger configuration for `Job` |
| `trigger.type` | string | no | Currently limited to `http` |
| `trigger.path` | string | no | Trigger path; schema default is `/run` |
| `spec` | object | no in the CRD schema | Native Kubernetes object preserved without structural pruning |

The runtime expects `orchestration.spec` to contain a complete Kubernetes
object matching `orchestration.type`. It substitutes mapped inputs, injects the
runtime namespace and ownership labels, and then creates the object.

## Values validation

`values.schema.json` validates the externally supplied settings that are
required by templates:

- `external.host`, `external.httpPort`, and `external.httpsPort`;
- `ingressClassName`;
- `auth.allowedRegistrationTypes`;
- authentication fields required by the selected registration types; and
- the current experimental TLS value structure.

Supported registration type values are `none`, `authorization_code`,
`device_code`, `provision`, and `client_credentials`.
