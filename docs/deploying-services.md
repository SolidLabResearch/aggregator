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
- Deployment catalog endpoint: `http://aggregator.local/deployments`
- Aggregator instance: `http://aggregator.local/agg1`
- Service collection endpoint: `http://aggregator.local/agg1/services`

## 1. Check Supported Deployment Functions

Before deploying a service, verify which deployment functions are supported by the Aggregator Server.

### Request

```http
GET http://aggregator.local/deployments
Accept: text/turtle
```

### Example Response

```turtle
@base <http://aggregator.example.org/deployments#> .
@prefix aggr: <https://w3id.org/aggregator#> .
@prefix dct: <http://purl.org/dc/terms/> .
@prefix fno: <https://w3id.org/function/ontology#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .

<> a aggr:DeploymentCatalog ;
    dct:title "Aggregator deployment functions" ;
    aggr:hasDeploymentFunction <DeployIncrementalKvasir> .

<DeployIncrementalKvasir>
  a fno:Function ;
  fno:expects ( <Query> <Sources> <Schema> <Context> ) ;
  fno:returns ( <DeployedService> ) .

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

<DeployedService>
  a fno:Output ;
  fno:predicate <service> ;
  fno:type aggr:Service .
```

This response describes the available deployment functions and their required inputs.

## 2. Create a Service

To deploy a service, send an `aggr:ServiceRequest` to the Aggregator’s service collection endpoint. It specifies:

- The deployment function to invoke
- The required input parameters

### Request

```http
POST http://aggregator.local/agg1/services
Content-Type: text/turtle

@prefix aggr: <https://w3id.org/aggregator#> .
@prefix deploy: <http://aggregator.example.org/deployments#> .

<http://aggregator.local/agg1/my-service> a aggr:ServiceRequest ;
  aggr:deploymentFunction deploy:DeployIncrementalKvasir ;
  deploy:query "SELECT ?s WHERE { ?s a <http://example.org/Person> }" ;
  deploy:sources "http://example.org/kvasir" ;
  deploy:schema "...schema definition..." ;
  deploy:context "...context definition..." .
```

---

If the request is successful, the Aggregator responds with:

- HTTP status `201 Created`
- A Service Description containing metadata and endpoints

### Example Response

```turtle
@prefix aggr: <https://w3id.org/aggregator#> .
@prefix dcat: <http://www.w3.org/ns/dcat#> .
@prefix deploy: <http://aggregator.example.org/deployments#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .

<http://aggregator.local/agg1/my-service>
  a aggr:Service, dcat:DataService ;
  aggr:status "running" ;
  aggr:createdAt "2024-01-01T12:00:00Z"^^xsd:dateTime ;
  aggr:deploymentFunction deploy:DeployIncrementalKvasir ;
  dcat:servesDataset <http://aggregator.local/agg1/my-service#result> .

<http://aggregator.local/agg1/my-service#result>
  a dcat:Dataset ;
  dcat:distribution <http://aggregator.local/agg1/my-service#result-distribution> .

<http://aggregator.local/agg1/my-service#result-distribution>
  a dcat:Distribution ;
  dcat:accessURL <http://aggregator.local/agg1/my-service/result> ;
  dcat:accessService <http://aggregator.local/agg1/my-service> .
```

## 3. Monitor Service Status

The Service Description is also available at the Service Endpoint (`http://aggregator.local/agg1/my-service`), which can be used to monitor the service status and access results.

## 4. Accessing Results

The Service Description includes one or more output predicates (such as `tf:result`) that indicate where the service output can be accessed.

For example, the query results are available at:

`http://aggregator.local/agg1/my-service/result`
