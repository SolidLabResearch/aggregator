# Deploying and accessing services

An aggregator instance exposes a service collection at:

```text
https://<host>/<aggregator-id>/services
```

Requests require the UMA scopes described in [UMA policies](uma-policies.md)
unless authentication is disabled.

## Discover deployment functions

List the public definitions and retrieve the definition you plan to use:

```http
GET https://<host>/deployments
Accept: text/turtle

GET https://<host>/deployments/fetch-profiled
Accept: text/turtle
```

The deployment document declares its parameters with FnO. Parameter predicates
are fragments of the deployment URL; for example:

```turtle
<https://<host>/deployments/fetch-profiled#url>
  a fno:Parameter ;
  fno:predicate <https://<host>/deployments/fetch-profiled#url> ;
  fno:type xsd:anyURI ;
  fno:required true .
```

Use the exact deployment and predicate IRIs returned by the catalog.

## Create a service

POST Turtle or JSON-LD to the collection. The request subject determines the
service name and must be below that collection.

```http
POST https://<host>/<aggregator-id>/services
Content-Type: text/turtle

@prefix aggr: <https://w3id.org/aggregator#> .

<https://<host>/<aggregator-id>/services/fetch-1>
  a aggr:ServiceRequest ;
  aggr:deploymentFunction <https://<host>/deployments/fetch-profiled> ;
  <https://<host>/deployments/fetch-profiled#url> <https://example.org/data> .
```

On success the server returns `201 Created`, a `Location` header, and the RDF
service description. The workload is created asynchronously in the
aggregator's Kubernetes namespace.

The CLI performs catalog discovery and encodes values using their declared FnO
types:

```bash
agg create-service \
  --name fetch-1 \
  --deployment-function fetch-profiled \
  --param url=https://example.org/data
```

## Inspect and delete services

```http
GET https://<host>/<aggregator-id>/services
GET https://<host>/<aggregator-id>/services/fetch-1
HEAD https://<host>/<aggregator-id>/services/fetch-1
DELETE https://<host>/<aggregator-id>/services/fetch-1
```

The collection response is JSON containing a `services` array. A service
response is Turtle and includes dataset distributions and their resolved
`dcat:accessURL` or `dcat:downloadURL` values. Use those advertised URLs rather
than constructing output paths yourself.

With the CLI:

```bash
agg get-service --svc fetch-1
agg list-outputs --svc fetch-1
agg get-output <dataset>/<distribution> --svc fetch-1
agg delete-service --svc fetch-1
```

Operational endpoints and dataset distributions are distinct. Only
distributions appear in `list-outputs`; other endpoints are documented by the
selected profile or inline interface.
