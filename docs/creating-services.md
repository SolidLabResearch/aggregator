# Creating Aggregator Services

This section will explain how to create a service that can run as an Aggregator Service.

An aggregator service **MUST** be a Dockerfile that:
  - accepts input parameters as environment variables
  - provides output parameters as endpoints

## Using the Egress UMA Proxy

When an Aggregator Service sends outbound requests to access UMA Resources, the UMA flow is handled by the `egress-uma-proxy`. A service must use the `HTTP_PROXY`, `http_proxy`, `HTTPS_PROXY` and `https_proxy` environment variables to route outgoing requests to the `egress-uma-proxy`.

The current `egress-uma-proxy` is still under development and therefore expects a special request format to perform outgoing requests.

You must specify the target method, url and if applicable body. For example, sending a POST request to `http://example.com/kvasir/query`:

```http
POST /fetch
Host: HTTP_PROXY / HTTPS_PROXY
Content-Type: application/json

{
  target_url: "http://example.com/kvasir/query",
  target_method: "POST",
  target_headers: { "Content-Type": "application/json" },
  target_body: {
    "@context": {},
    query: "query { resources { id } }"
  }
}
```

## Creating a Transformation Description

An Aggregator Service **MUST** be described as an [FnO Function](https://fno.io/spec/#ontology-abstract). Every parameter given as a environment variable, as well as every output provided as an endpoint must be included in the description.

## Creating a Transformation CRD

The Aggregator Server uses Custom Resource Defintions to load supported services. A CRD needs the following:
  - **name**: a abstract name for the service
  - **spec**:
    - **id**: the unique ID that identifies the transformation in the transformation catalog
    - **image**: the image name that implements the service as it is loaded inside the cluster
    - **fno**: the FnO description of the transformation. Function, Parameter, Output and predicate defintions should expect an `@base` prefix. This will be set to the transformation catalog once the CRD is loaded inside the Aggregator Server.
    - **input mapping**: mapping each parameter predicate onto the environment variable to be used
    - **output mapping**: mapping each output predicate onto the path and port to be used to fetch the ouput values

Transformations are added in the Aggregator Server helm file using the `transformations` keyword:

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