# Demo

If you have completed the local setup guide, you should now how to have a local kind cluster running and deploy the aggregator-platform.

This demo is designed for the **PACSOI** project and assumes:

- A running **UMA server**
- A running **Keycloak authorization server**

## 1. Keycloak configuration

The aggregator must be registered in Keycloak as a **confidential client**.

Make sure:
- The client type is **confidential**
- **Device Authorization Grant** is enabled

During local setup, verify that [/kind/helm-config.yaml](/kind/helm-config.yaml) contains the correct values:

```yaml
auth:
  server: <keycloak instance>
  clientId: <aggregator client id>
  clientSecret: <aggregator client secret>
  allowedRegistrationTypes:
    - device_code
```

### Demo scripts: UMA flow

Some API endpoints are protected using **UMA (User-Managed Access)**.
The demo scripts handle the UMA authorization flow automatically, but you must provide valid credentials before running them.

Therefore you will also need a separate confidential client with **Direct Access Grants** to interact with the aggregator platform programmatically.

Before executing a demo script ensure the following constants are configured correctly:
```ts
const USERNAME = "<aggregator owner username>";
const PASSWORD = "<aggregator owner password>";
const CLIENT_ID = "<demo client id>";
const CLIENT_SECRET = "<demo client secret>";
const IDP = "<keycloak instance>";
const REALM = "<keycloak realm>";
```

## 2. FnO Transformations

The aggregator platform supports **FnO (Function Ontology) transformations**, which define computational functions and how they are executed inside the cluster.

You can configure available transformations in the [helm config file](/kind/helm-config.yaml).

---
### Example Transformation
```yaml
transformations:
  - name: pacsoi
    spec:
      id: Pacsoi
      image: pacsoi-mock-service
      fno: |
        @prefix fno: <https://w3id.org/function/ontology#> .
        @prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
        @prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .

        <Pacsoi>
          a fno:Function ;
          fno:expects ( ) ;
          fno:returns ( <WeightDistribution> ) .

        <WeightDistribution>
          a fno:Output ;
          fno:predicate <w-distribution> .
      inputMapping: {}
      outputMapping:
        w-distribution:
          port: 8000
          path: /report
```
---
### How Transformations Work

1. **Function ID and Implementation**

    - Each FnO Function is identified by an id and linked to its implementation via the image field.
    - The implementation image must be available inside the cluster (preloaded or built).

2. **Parameters**

    - Each function lists its expected parameters.
    - Parameters are currently expected to be string values.
    - Each parameter has a predicate (used when creating services) and an inputMapping, which specifies the environment variable that the function implementation expects.

3. **Outputs**

    - Functions define outputs with associated predicates.
    - The outputMapping specifies how the implementation exposes the result (e.g., port and path).

4. **Execution Flow**

    - When a service is created using a transformation, the aggregator maps input values to environment variables, runs the implementation, and exposes outputs according to the output mapping.

Function, Parameter, Output and predicate URIs are expected to use the `@base` prefix, which is automatically set to the aggregator transformations endpoint when loading transformations.

## 3. Creating an aggregator for a user

To create an aggregator for a user, initiate device registration:
```pgsql
POST https://aggregator.local/registration
Content-Type: application/json

{
  "registration_type": "device_code",
  "authorization_server": "<UMA instance>"
}
```

You will recieve:
```json
{
  state: <state>,
  user_code: <user_code>,
  verification_uri: <verification_uri>,
  verification_uri_complete: <verification_uri_complete>
}
```

### User Authorization Step

- The user visits verification_uri
- Enters the user_code
- Logs in (or registers)
- Grants consent to the aggregator

---
### Finalizing Registration

While the user is authorizing, you can poll the registration endpoint with the received state:
```pqsql
POST https://aggregator.local/registration
Content-Type: application/json

{
  "registration_type": "device_code",
  "state": "<state>"
}

```
If registration is still pending or the aggregator is being deployed, you will receive:
```HTTP 202 Accepted```

If successful, you will receive:
```json
{
  id: <aggregator-id>
  aggregator: <aggregator-base-iri>
}
```

If an error occured, you will recieve:
```HTTP 400 Bad Request```

---
### Demo script
This flow is implemented in [demo/pacsoi/register-user](/demo/pacsoi/register-user.ts). Ensure the following constants are set correctly:

```ts
REGISTARTION = "https://aggregator.local/registration"
AS_URL = <UMA instance>
```
Then run:
```bash
npm run register-user
```

## 4. Creating a service inside the aggregator

To create a service inside an aggregator, you send an FnO Execution to the aggregator’s service collection endpoint (UMA-protected):

```pgsql
POST https://aggregator.local/<aggregator-id>/services
Content-Type: text/turtle

@prefix trans: <https://aggregator.local/transformations#>.
@prefix fno: <https://w3id.org/function/ontology#>.
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>.
@prefix xsd: <http://www.w3.org/2001/XMLSchema#>.

<https://aggregator.local/<aggregator-id>/service-id> a fno:Execution;
    fno:executes <Fno Function>;
    <input predicate> "<input value>";
    ...
```

---
### Example
```
@prefix trans: <https://aggregator.local/transformations#>.
@prefix fno: <https://w3id.org/function/ontology#>.
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>.
@prefix xsd: <http://www.w3.org/2001/XMLSchema#>.

<https://aggregator.local/15359d0a-df50-4083-8c88-b457ec7d2399/pacsoi-service> a fno:Execution;
    fno:executes trans:Pacsoi;
```

---
### Demo script
This flow is implemented in [demo/pacsoi/create-service](/demo/pacsoi/create-service.ts). Ensure the following constants are set correctly:

```ts
const AGGREGATOR = "https://aggregator.local/<aggregator-id>";

const SVC_NAME = "<service-id>"
const TF_ID = "<Fno Function>"
const PARAMS = {
  "<inptu pred>": "<input value>",
  ...
} // Pacsoi service does not require inputs, so this can be left empty
```
Then run:
```bash
npm run create-service
```

## 5. Fetching service output

Once a service is running, you can fetch its outputs by combining the **service ID** with the **output predicate** (UMA Protected):

```
GET https://aggregator.local/<aggregator-id>/<service-id>/<output pred>
```

---
### Demo script
This flow is implemented in [demo/pacsoi/get-service](/demo/pacsoi/get-service.ts). Ensure the following constants are set correctly:

```ts
const SERVICE_ENDPOINT = "https://aggregator.local/<aggregator-id>/<service-id>";
// ex. https://aggregator.local/15359d0a-df50-4083-8c88-b457ec7d2399/pacsoi-service
const OUTPUT_ENDPOINT = "https://aggregator.local/<aggregator-id>/<service-id>/<output pred>";
// ex. https://aggregator.local/15359d0a-df50-4083-8c88-b457ec7d2399/pacsoi-service/w-distribution
```
Then run:
```bash
npm run get-service
```