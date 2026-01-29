# Aggregation Platform Helm Chart

This Helm chart deploys the **Aggregation Server**. This server allows to deploy **Aggregators** for authenticated users. A user can deploy **FnO Pipelines** inside his aggregator to aggregate UMA-protected resources.

---

### Values

Below is a detailed description of all configurable parameters.

### General

| Parameter  | Description                           | Default        |
| ---------- | ------------------------------------- | ---------------|
| `host`     | Host name of the aggregator platform | N/A (required) |
| `loglevel` | Log level of the aggregator platform | `info`         |

### Registration Configuration

Configure authorization for creating new aggregators.

| Parameter | Description |
| - | - |
| `auth.server` | OIDC server URL |
| `auth.clientId` | OIDC client ID |
| `auth.clientSecret` | OIDC client secret |
| `auth.allowedRegistrationTypes` | List of allowed registration types: `none`, `device_code` |

- `none`: Create an unauthorized aggregator (development)
- `device code`: Enable authorization using the Device Authorization Grant

### Specification Configuration

Configure how the platform will implement the spec endpoints

| Parameter | Description | Default |
| - | - | - |
| `spec.service_collection` | URL path for service collection | `/services` |
| `spec.transformation_catalog` | URL path for transformation catalog | `/transformations` |
| `transformations` | List of available transformations | `[]` |

***Trnsformation example***

- The FnO Description should be given without `@base`
- `inputMapping` links parameters to ENV variables
- `outputMapping` links outputs to services

```yaml
transformations:
  - name: sparqlQuery
    spec:
      id: SparqlQuery     # The ID of the FnO Function
      image: incremunica  # The implementation to use
      # The FnO Description
      fno: |              
        @prefix fno: <https://w3id.org/function/ontology#> .
        @prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
        @prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .

        <SparqlQuery>
          a fno:Function ;
          fno:expects ( <Sources> <Query> ) ;
          fno:returns ( <Result> ) .

        <Sources>
          a fno:Parameter ;
          fno:predicate <sources> ;
          fno:type xsd:string ;
          fno:required "true"^^xsd:boolean .
        
        <Query>
          a fno:Parameter ;
          fno:predicate <query> ;
          fno:type xsd:string ;
          fno:required "true"^^xsd:boolean .

        <Result>
          a fno:Output ;
          fno:predicate <result> .
      inputMapping:
        sources: SOURCES
      outputMapping:
        result:
          port: 8080
          path: /
```

### TLS Configuration

TLS can be **disabled**, use **self-signed certs**, or use **cert-manager** for production

| Parameter | Description | Default |
| - | - | - |
| `tls.enabled` | Enable TLS | `false` |
| `tls.secretName` | Name of the secret containing TLS cert/key | `aggregator-tls`          |
| `tls.mode` | TLS mode (`selfsigned` or `cert-manager`)  | N/A (required if enabled) |

**Self-signed TLS Example**
```yaml
tls:
  enabled: true
  mode: selfsigned
  selfSigned:
    crt: tls.crt              # TLS certificate
    key: tls.key              # TLS private key
```
**Cert-manager TLS Example**
```yaml
tls:
  enabled: true
  mode: cert-manager
  certManager:
    issuerName: letsencrypt-prod
    issuerKind: ClusterIssuer     # "Issuer" or "ClusterIssuer"
    issuerGroup: cert-manager.io
    duration: 2160h               # Optional certificate validity
    renewBefore: 720h             # Optional renew-before duration
```

### Server Configuration
| Parameter | Description | Default |
| -| -| - |
| `server.replicaCount` | Number of Aggregator Server replicas | `1` |
| `server.image.repository` | Docker image repository | `aggregator-server` |
| `server.image.tag`        | Docker image tag | `latest` |
| `server.image.pullPolicy` | Image pull policy | `Never` |
| `server.readinessProbe`   | Readiness probe settings | See `values.yaml`   |

### Ingress-UMA Configuration
| Parameter | Description | Default |
| - | - | - |
| `ingressUma.replicaCount` | Number of Ingress-UMA replicas | `1` |
| `ingressUma.image.repository` | Docker image repository | `ingress-uma` |
| `ingressUma.image.tag` | Docker image tag | `latest` |
| `ingressUma.disableAuth` | Disable UMA authentication | `false` |
| `ingressUma.readinessProbe` | Readiness probe settings | See `values.yaml` |



