# Deploying Aggregator Services

This section explains how to deploy a service on a running Aggregator.

## Prerequisites

Before proceeding, make sure you have:

- Created a service (see [Creating Services](creating-services.md))
- Deployed and started an Aggregator (see [Deploying Aggregators](deploying-aggregators.md))
- Access to an account with the required permissions (see [UMA Policies](uma-policies.md))

## Assumed Setup

The examples in this guide assume the following configuration:

- Aggregator Server: `http://aggregator.local`
- Transformation catalog endpoint: `http://aggregator.local/transformations`
- Aggregator instance: `http://aggregator.local/agg1`
- Service collection endpoint: `http://aggregator.local/agg1/services`

## 1. Check Supported Transformations

Before deploying a service, verify which transformations are supported by the Aggregator Server.

### Request

```http
GET http://aggregator.local/transformations
Accept: text/turtle
```

### Example Response

```turtle
@base <http://aggregator.example.org/transformations#> .
@prefix aggr: <https://spec.knows.idlab.ugent.be/aggregator-protocol/latest/#> .
@prefix dct: <http://purl.org/dc/terms/> .
@prefix fno: <https://w3id.org/function/ontology#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .

<> a aggr:TransformationCatalog ;
    dct:title "Aggregator transformations" ;
    aggr:hasTransformation <IncrementalKvasir> .

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
```

This response describes the available transformations, including their required inputs and outputs.

## 2. Create a Service

To deploy a service, send a request to the Aggregator’s service collection endpoint. The request must be an `fno:Execution` that specifies:

- The transformation to execute
- The required input parameters

### Request

```http
POST http://aggregator.local/agg1/services
Content-Type: text/turtle

@prefix fno: <https://w3id.org/function/ontology#> .
@prefix tf: <http://aggregator.example.org/transformations#> .

<http://aggregator.local/agg1/my-service> a fno:Execution ;
  fno:executes tf:IncrementalKvasir ;
  tf:query "SELECT ?s WHERE { ?s a <http://example.org/Person> }" ;
  tf:sources "http://example.org/kvasir" ;
  tf:schema "...schema definition..." ;
  tf:context "...context definition..." .
```

---

If the request is successful, the Aggregator responds with:

- HTTP status `201 Created`
- A Service Description containing metadata and endpoints

### Example Response

```turtle
@prefix aggr: <https://spec.knows.idlab.ugent.be/aggregator-protocol/latest/#> .
@prefix fno: <https://w3id.org/function/ontology#> .
@prefix tf: <http://aggregator.example.org/transformations#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .

<http://aggregator.local/agg1/my-service>
  a aggr:Service ;
  a fno:Execution ;
  aggr:status "running" ;
  aggr:createdAt "2024-01-01T12:00:00Z"^^xsd:dateTime ;
  fno:executes tf:IncrementalKvasir ;
  tf:query "SELECT ?s WHERE { ?s a <http://example.org/Person> }" ;
  tf:sources "http://example.org/kvasir" ;
  tf:schema "...schema definition..." ;
  tf:context "...context definition..." ;
  tf:result <http://aggregator.local/agg1/my-service/result> .
```

## 3. Monitor Service Status

The Service Description is also available at the Service Endpoint (`http://aggregator.local/agg1/my-service`), which can be used to monitor the service status and access results.

## 4. Accessing Results

The Service Description includes one or more output predicates (such as `tf:result`) that indicate where the service output can be accessed.

For example, the query results are available at:

`http://aggregator.local/agg1/my-service/result`
