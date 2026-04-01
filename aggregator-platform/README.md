# Aggregator Platform Helm Chart

This Helm chart deploys the **Aggregator Platform**, consisting of:

**Aggregator Server** – manages aggregators
**Ingress-UMA** – handles UMA-protected access
**Token Service** – issues and manages tokens

The platform allows authenticated users to deploy **Aggregators**, in which they can run **FnO Services** to aggregate UMA-protected resources.

## Configuration

Below is a detailed overview of all configurable parameters.

---

### External Access

Defines how the platform is exposed externally. At least one external access port (HTTP or HTTPS) must be configured.

| Parameter | Description | Required |
| - | - | - |
| `external.host` | Public hostname of the platform | ✅ |
| `external.httpPort` | HTTP port | ⚠️ |
| `external.httpsPort` | HTTPS port | ⚠️ |
| `ingressClassName` | Kubernetes ingress class name | |

---

#### TLS Configuration

Configure HTTPS support.

| Parameter | Description | Default |
| - | - | - |
| `tls.enabled` | Enable TLS | `false` |
| `tls.mode` | TLS mode (`selfsigned` or `cert-manager`) | Required if enabled |
| `tls.secretName` | Kubernetes secret for TLS certs | Required if enabled |

```yaml
tls:
  enabled: true
  mode: selfsigned
  secretName: aggregator-tls
```

***Self-Signed TLS***

```yaml
tls:
  enabled: true
  mode: selfsigned
  secretName: aggregator-tls
  selfSigned:
    crt: <base64-cert>
    key: <base64-key>
```

---

### General

| Parameter | Description | Default |
| - | - | - |
| `loglevel` | Log level of the platform | `info` |

---

### Authentication Configuration

Controls how users can register new aggregators.

| Parameter | Description |
| - | - |
| `auth.allowedRegistrationTypes` | Allowed registration flows |

Supported registration types:

- `none` – No authentication (development only)
- `authorization_code` – Standard OIDC authorization code flow
- `device_code` – Device Authorization Grant
- `provision` – Pre-provisioned credentials

---

#### OIDC Configuration

Used for OIDC-based flows (`authorization_code`, `device_code`).

| Parameter | Description |
| - | - |
| `auth.oidc.server` | OIDC provider URL |
| `auth.oidc.clientId` | OIDC client ID |
| `auth.oidc.clientSecret` | OIDC client secret |
| `auth.solidOidc` | Enable Solid-OIDC behavior | `true` |

---

#### Provision Configuration

Required when using `provision`.

| Parameter | Description |
| - | - |
| `auth.provision.clientId` | Client ID |
| `auth.provision.clientSecret` | Client secret |
| `auth.provision.webId` | WebID of the provisioned agent |
| `auth.provision.authServer` | Authorization server |

---

### Specification Configuration

Controls the exposed API paths and available transformations.

| Parameter | Description | Default |
| - | - | - |
| `spec.service_collection` | Service collection endpoint | `/services` |
| `spec.transformation_catalog` | Transformation catalog endpoint | `/transformations` |
| `spec.registration` | Registration endpoint | `/registration` |
| `transformations` | List of available transformations | `[]` |



***Transformation example***

- The FnO Description **must not include** `@base`
- `image` specifies the container image to use for this transformation
- `id` is the FnO Function ID (without the base URI)
- `inputMapping` maps parameters to environment variables
- `outputMapping` maps outputs to container endpoints

```yaml
transformations:
  - name: incremental-kvasir
    spec:
      id: IncrementalKvasir
      image: incremunica-kvasir
      fno: |
        @prefix fno: <https://w3id.org/function/ontology#> .
        @prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
        @prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .

        <IncrementalKvasir>
          a fno:Function ;
          fno:expects ( <Query> <Sources> <Schema> <Context> ) ;
          fno:returns ( <QueryResult> ) .

        <Query>
          a fno:Parameter ;
          fno:type xsd:string ;
          fno:predicate <query> ;
          fno:required "true"^^xsd:boolean .
        
        <Sources>
          a fno:Parameter ;
          fno:type xsd:string ;
          fno:predicate <sources> ;
          fno:required "true"^^xsd:boolean .
        
        <Schema>
          a fno:Parameter ;
          fno:type xsd:string ;
          fno:predicate <schema> ;
          fno:required "true"^^xsd:boolean .
        
        <Context>
          a fno:Parameter ;
          fno:type xsd:string ;
          fno:predicate <context> ;
          fno:required "true"^^xsd:boolean .
        
        <QueryResult>
          a fno:Output ;
          fno:predicate <result> .
      inputMapping:
        query: QUERY
        sources: SOURCES
        schema: SCHEMA
        context: CONTEXT
      outputMapping:
        result:
          port: 3000
          path: /
```

### Aggregator Server Configuration
| Parameter | Description | Default |
| - | - | - |
| `server.replicaCount` | Number of replicas | `1` |
| `server.image.repository` | Docker image | `aggregator-server` |
| `server.image.tag` | Image tag | `latest` |
| `server.image.pullPolicy` | Pull policy | `Never` |
| `server.readinessProbe` | Readiness probe config | See `values.yaml` |

### Ingress-UMA Configuration
| Parameter | Description | Default |
| - | - | - |
| `ingressUma.replicaCount` | Number of replicas | `1` |
| `ingressUma.image.repository` | Docker image | `ingress-uma` |
| `ingressUma.image.tag` | Image tag | `latest` |
| `ingressUma.image.pullPolicy` | Pull policy | `Never` |
| `ingressUma.disableAuth` | Disable UMA authentication | `false` |
| `ingressUma.readinessProbe` | Readiness probe config | See `values.yaml` |
| `ingressUma.terminationGracePeriodSeconds` | Shutdown grace period | `50` |

### Token Service Configuration
| Parameter | Description | Default |
| - | - | - |
| `tokenService.replicaCount` | Number of replicas | `1` |
| `tokenService.image.repository` | Docker image | `token-service` |
| `tokenService.image.tag` | Image tag | `latest` |
| `tokenService.image.pullPolicy` | Pull policy | `Never` |
| `tokenService.readinessProbe` | Readiness probe config | See `values.yaml` |
| `tokenService.terminationGracePeriodSeconds` | Shutdown grace period | `60` |




