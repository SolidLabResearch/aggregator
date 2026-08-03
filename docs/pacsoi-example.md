# Pacsoi Demo

The following demo will help you set up the Pacsoi Demo. This example assumes you have a running KSS and UMA Server (see [kss-setup](kss-setup.md) for a local setup guide).

This demo will assume the following configuration:

  - Authentication:
    - **keycloak realm**: `http://localhost:8280/realms/quarkus`
    - **aggregator client ID**: `aggregator-server`
    - **aggregator client secret**: `01234`
    - **demo client ID**: `demo-client`
    - **demo client secret**: `56789`
    - Users:
      - Patient:
        - **username**: patient
        - **password**: patient
        - **user ID**: `00-00-00`
      - Doctor:
        - **username**: doctor
        - **password**: doctor
        - **user ID**: `11-11-11`
  - KSS:
    - **server URL**: `http://localhost:8080/`
    - Pods:
      - Patient pod:
        - **pod ID**: `patient`
        - **pod URL**: `http://localhost:8080/patient`
      - Doctor pod:
        - **pod ID**: `doctor`
        - **pod URL**: `http://localhost:8080/doctor`
  - Aggregator cluster:
    - ingress class name: `aggregator-traefik`
    - cluster http port: `5080`
    - cluster https port: `5443`
    - host: `aggregator.local`

This demo assumes that the following slices with data are available:

  - Doctor Pod:
    - **PatientSlice**: A slice containing a list of patient pods that the doctor must manage.
  - Patient Pod:
    - **MetadataSlice**: A slice with the patient's metadata: age, birth, gender
    - **ProcedureSlice**: A slice with the patient's her procedures
    - **WeightObservationsSlice**: A slice with weight observations of the patient
    - **OxfordQuestionnaireResponseSlice**: A slice with questionnare responses of the patient
  
## Set Up the Aggregator Server

## Set Up the Doctor Aggregator

### Register the Doctor

A doctor must have an aggregator to monitor all its patients. Send the following request to the aggregator 
**registration endpoint**.

```http
POST /registration
Host: https://aggregator.local:5443
Content-Type: application/json

{
  registration_type: "device_code",
  authorization_server: "http://localhost:4000/uma",
}
```

The server will initiate a [Device Code flow](https://auth0.com/docs/get-started/authentication-and-authorization-flow/device-authorization-flow#device-flow). Go to the verification URI, enter the code and log in using the doctor credentials. Use the provided *state* to poll registration and setup status. If completed you will recieve the location of the doctor's aggregator.

Let's assume the aggregator was created at `https://aggregator.local:5443/doc-aggregator`

### Set up Aggregator Service

Now set up the aggregator service:

```http
POST /doc-aggregator/services
Host: https://aggregator.local:5443
Content-Type: text/turtle

@prefix aggr: <https://w3id.org/aggregator#> .
@prefix deploy: <https://aggregator.local:5443/deployments#> .

<https://aggregator.local:5443/doc-aggregator/Pacsoi-Service> 
  a aggr:ServiceRequest ;
  aggr:deploymentFunction deploy:Pacsoi ;
  deploy:sources <http://localhost:8080/doctor/PatientSlice> ;
  deploy:weight-slice "WeightObservationsSlice" ;
  deploy:procedure-slice "ProcedureSlice" .
```

### Access Aggregator Service

Now you can get the service results from the following endpoints:

- weight distributions: `https://aggregator.local:5443/doc-aggregator/Pacsoi-Service/weight-dist`
- oxford scores: `https://aggregator.local:5443/doc-aggregator/Pacsoi-Service/oxford`
