# UMA Policies

This section describes the minimal UMA policies required to deploy and manage services on an Aggregator.

These policies ensure that only authorized users can:
- Create services
- View service status
- Delete services
- Access service results

By default, the Aggregator automatically creates these policies for the user who deployed it. If you are using a different account, you must configure the required permissions via the authorization server API.

## Assumed Setup

The examples in this guide assume the following configuration:

- Aggregator instance: `http://aggregator.local/agg1`
- Service collection endpoint: `http://aggregator.local/agg1/services`
- Service endpoint: `http://aggregator.local/agg1/my-service`
- Service result endpoint: `http://aggregator.local/agg1/my-service/result`
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
- target: `http://aggregator.local/agg1/services/<service id>`
- assigner: `<user id>`
- assignee: `<owner id>`

---

### 3. Delete Service

Allows removing a service.

- scopes: `delete`
- target: `http://aggregator.local/agg1/services/<service id>`
- assigner: `<user id>`
- assignee: `<owner id>`

---

### 4. Access Service Results

Allows retrieving the output of a service.

- scopes: `read`
- target: `http://aggregator.local/agg1/my-service/result`
- assigner: `<user id>`
- assignee: `<owner id>`
