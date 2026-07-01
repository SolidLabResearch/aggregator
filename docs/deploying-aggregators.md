# Deploying Aggregator Instances

This document will show how to deploy an Aggregator on a running Aggregator Server.

Setting up an aggregator is done using the endpoint advocated with `registration_endpoint` at the discovery endpoint. The rest of this document assumes this endpoint is at `/registration`.

Updating an existing aggregator is done by including the `aggregator_id` field in any registration request. See [Updating Aggregators](updating-aggregators.md) for more details.

## Device Code Flow

The **Device Code Flow** is currently supported only for the **OIDC flow**. This requires a standard OpenID Connect Identity Provider (for example, Keycloak—see [Keycloak Authentication](/docs/kss-setup.md#setting-up-keycloak)).

The aggregator must be configured to support the Device Code Flow:

```yaml
auth:
  allowedRegistrationTypes:
    - device_code
```

---

### 1. Initiate Device Registration

```http
POST /registration
Content-Type: application/json

{
  "registration_type": "device_code",
  "authorization_server": "<UMA instance>"
}
```

#### Responses

✅ **202 Accepted**

```json
{
  "state": "<state>",
  "user_code": "<user_code>",
  "verification_uri": "<verification_uri>",
  "verification_uri_complete": "<verification_uri_complete>",
  "expires_in": "<expires_in>",
  "interval": "<interval>"
}
```

- `state`: Unique identifier for tracking the registration process
- `user_code`: Code the user must enter to authorize
- `verification_uri`: URL where the user completes authorization
- `verification_uri_complete`: Pre-filled URL including the user code
- `expires_in`: Seconds until the device code expires
- `interval`: Minimum seconds to wait between polling requests

❌ **500 Internal Server Error**

Returned if the authorization server is unreachable or misconfigured.

---

### 2. User Authorization

The user must complete the following steps:

1. Navigate to `verification_uri` (or use `verification_uri_complete`)
2. Enter the `user_code` (if not already included)
3. Log in or register with the Identity Provider
4. Grant consent to the aggregator

---

### 3. Finalizing Registration

While the user is completing authorization, poll the registration endpoint using the `state` returned in step 1. Wait at least `interval` seconds between requests.

```http
POST /registration
Content-Type: application/json

{
  "registration_type": "device_code",
  "state": "<state>"
}
```

#### Responses

⏳ **202 Accepted**

Returned while the user has not yet completed authorization or the aggregator is still being deployed. Continue polling.

✅ **201 Created**

```json
{
  "aggregator_id": "<aggregator-id>",
  "aggregator": "<aggregator-base-iri>",
  "subject": "<user-id>",
  "idp": "<oidc-server>"
}
```

❌ **400 Bad Request**

Returned if the `state` is invalid or not found.

❌ **500 Internal Server Error**

Returned if the aggregator server fails to fetch the token, store credentials, or deploy the aggregator.

---

## Token Exchange Flow

The **Token Exchange Flow** is currently supported only for the **OIDC flow**. This requires a standard OpenID Connect Identity Provider (for example, Keycloak—see [Keycloak Authentication](/docs/kss-setup.md#setting-up-keycloak)).

The aggregator must be configured to support the Token Exchange Flow:

```yaml
auth:
  allowedRegistrationTypes:
    - token_exchange
```

---

### Initiate Token Exchange Registration

The subject token must:
- Be obtained from the Identity Provider via an interactive login (authorization code flow)
- Include `openid` and `offline_access` scopes
- Have the aggregator client registered as an audience

```http
POST /registration
Content-Type: application/json
Authorization: Bearer <subject-token>

{
  "registration_type": "token_exchange",
  "authorization_server": "<UMA instance>"
}
```

#### Responses

✅ **201 Created**

```json
{
  "aggregator_id": "<aggregator-id>",
  "aggregator": "<aggregator-base-iri>",
  "subject": "<user-id>",
  "idp": "<oidc-server>"
}
```

🔒 **401 Unauthorized**

Returned if the subject token is missing, invalid, expired, or lacks the required scopes or audience.

❌ **500 Internal Server Error**

Returned if the aggregator server fails to exchange the token, store credentials, or deploy the aggregator.

## Authorization Code Flow

Under construction.

## Provision Flow

Under construction.

## Listing available aggregators

To list available aggregators, send a `GET` request to the registration endpoint:
  - Add an `Authorization` header to list all aggregators you have access to
  - Omit the `Authorization` header to list public aggregators

```http
GET /registration
```

#### Response

```json
{
  "aggregators": [
    <aggregator-base-iri-1>,
    ...
  ]
}
```