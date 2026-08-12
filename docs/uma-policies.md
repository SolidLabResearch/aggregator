# UMA Policies

This section describes the minimal UMA policies required to deploy and manage services on an Aggregator.

These policies ensure that only authorized users can:
- Create services
- View service status
- Delete services
- Access service results

By default, the Aggregator automatically creates these policies for the user who deployed it. If you are using a different account, you must configure the required permissions via the authorization server API.

## Default policy API

Each Aggregator exposes a `/policies` collection for reusable default policies.
Its public URL is the Aggregator base URL followed by `/policies`, and the path
is registered as a protected resource when the Aggregator is deployed.

A default policy is a complete JSON-LD ODRL `Offer` or `Agreement` template and
can contain profiles, assignees, duties, remedies, and arbitrary constraints.
Its permissions must omit `odrl:action`, `odrl:target`, and `odrl:assigner`.
The Aggregator supplies those fields for each resource: actions come from the
resource's scopes, the target is its UMA resource identifier, and the assigner
is the Aggregator-controlled subject.

Instantiated policies, permissions, and nested JSON-LD nodes receive unique
`urn:uuid:` identifiers. Before submission to UMA, any blank nodes introduced
by JSON-LD expansion are replaced with `urn:uuid:` identifiers, so no blank
nodes reach the authorization server.

Creating a policy applies it to every resource already registered by the
Aggregator. It is also applied automatically to service descriptions,
distributions, operational endpoints, and other resources registered later.
Policy-management resources are the exception: `/policies` and individual
`/policies/<policy-id>` resources receive only the automatically created owner
Agreement. User-created default policies can therefore grant access to services
and data, but cannot grant permission to list, create, or delete policies.

```http
POST http://aggregator.local/agg1/policies
Content-Type: application/ld+json

{
  "@context": [
    "http://www.w3.org/ns/odrl.jsonld",
    {
      "gx": "https://registry.lab.gaia-x.eu/development/api/trusted-shape-registry/v1/shapes/jsonld/trustframework#",
      "ovc": "https://w3id.org/gaia-x/ovc/1/"
    }
  ],
  "@type": "Offer",
  "uid": "http://example.com/policy/123",
  "profile": "https://w3id.org/gaia-x/ovc/1/",
  "permission": [
    {
      "@type": "Permission",
      "ovc:constraint": [
        {
          "ovc:leftOperand": "$.credentialSubject.gx:legalAddress.gx:countrySubdivisionCode",
          "operator": "http://www.w3.org/ns/odrl/2/isAnyOf",
          "rightOperand": ["FR-HDF", "BE-BRU"],
          "ovc:credentialSubjectType": "gx:LegalParticipant"
        }
      ]
    }
  ]
}
```

The response is `201 Created`, includes the policy URL in `Location`, and
returns the unchanged JSON-LD template. `GET` returns a JSON-LD array of active
templates. Each entry includes
`https://w3id.org/aggregator#policyId`, the management identifier used in its
delete URL; this is separate from the policy's ODRL `uid`.

List active defaults or delete one by its identifier:

```http
GET http://aggregator.local/agg1/policies

DELETE http://aggregator.local/agg1/policies/<policy-id>
```

The CLI provides shortcuts for listing policies and creating a default
Agreement for an assignee:

```bash
agg list-policies
agg add-default-agreement https://example.org/alice/profile/card#me
```

Both commands use the active Aggregator by default. Pass `--agg <id>` to select
another configured Aggregator.

Deleting a default revokes its instantiated permissions from existing
resources and prevents it from being applied to new resources. The owner policy
is created automatically when the Aggregator starts and is returned by `GET`.

## Service role grants

The owner can grant one role advertised by a deployed service. The Agreement
template omits `odrl:target`, `odrl:action`, and `odrl:assigner`; the Aggregator
derives exact targets and actions from the profile and deployed routes.

```http
POST http://aggregator.local/agg1/policies/grants?service=services-weight-aggregation&role=training-client
Content-Type: application/ld+json

{
  "@context": "http://www.w3.org/ns/odrl.jsonld",
  "@type": "Agreement",
  "uid": "urn:uuid:29f8d99d-37de-47ba-9f34-b7aa1d3bb77f",
  "permission": [{
    "@type": "Permission",
    "assignee": "https://example.org/participants/hospital-3"
  }]
}
```

`service` accepts a deployed service instance ID or URL. `role` accepts its
short profile name or full role IRI. List and revoke grants with:

```http
GET http://aggregator.local/agg1/policies/grants
DELETE http://aggregator.local/agg1/policies/grants/<grant-id>
```

Role grants are restricted to their selected service resources and cannot
confer access to the policy-management tree. The CLI equivalents are:

```bash
agg list-available-roles --svc weight-aggregation
agg list-active-roles --svc weight-aggregation
agg assign-role training-client https://example.org/participants/hospital-3 \
  --svc weight-aggregation
```

## Assumed Setup

The examples in this guide assume the following configuration:

- Aggregator instance: `http://aggregator.local/agg1`
- Service collection endpoint: `http://aggregator.local/agg1/services`
- Service endpoint: `http://aggregator.local/agg1/services/my-service`
- Distribution endpoint: the URL advertised by the service's
  `dcat:accessURL` or `dcat:downloadURL`
- `<owner id>`: user who deployed the Aggregator
- `<user id>`: user requesting access

## Authorization Server

During Aggregator deployment (see [Deploying Aggregators](deploying-aggregators.md)), you can configure which UMA authorization server is used to manage access to resources.

## Required Policies

### 1. Create Service

Allows creating new services.

- scopes: `create`
- target: `http://aggregator.local/agg1/services`
- assigner: `<user id>`
- assignee: `<owner id>`

---

### 2. Read Service

Allows checking the status or description of a service.

- scopes: `read`
- target: `http://aggregator.local/agg1/services/<service-id>`
- assigner: `<user id>`
- assignee: `<owner id>`

---

### 3. Delete Service

Allows removing a service.

- scopes: `delete`
- target: `http://aggregator.local/agg1/services/<service-id>`
- assigner: `<user id>`
- assignee: `<owner id>`

---

### 4. Access Service Results

Allows retrieving the output of a service.

- scopes: `read`
- target: the distribution URL advertised in the service description
- assigner: `<user id>`
- assignee: `<owner id>`
