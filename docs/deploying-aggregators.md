# Deploying Aggregator Instances

This document will show how to deploy an Aggregator on a running Aggregator Server.

Seting up an aggregator is done using the endpoint advocated with `registration_endpoint` at the discovery endpoint. The rest of this document assumes this endpoint is at `/registration`.

## Device Code Flow

The **Device Code Flow** is currently supported only for the **OIDC flow**. This requires a standard OpenID Connect Identity Provider (for example, Keycloak—see [Keycloak Authentication](/docs/kss-setup.md#setting-up-the-aggregator-server-authentication)).

The aggregator must be configured to support the Device Code Flow:

```yaml
auth:
  allowedRegistrationTypes:
    - device_code
```

---

### 1. Initate Device Registration

To create an aggregator for a user, start by initiating device registration:
```http
POST /registration
Content-Type: application/json

{
  "registration_type": "device_code",
  "authorization_server": "<UMA instance>"
}
```

#### Response

```json
{
  state: <state>,
  user_code: <user_code>,
  verification_uri: <verification_uri>,
  verification_uri_complete: <verification_uri_complete>
}
```

#### Field descriptions:

- `state`: Unique identifier for tracking the registration process
- `user_code`: Code the user must enter to authorize
- `verification_uri`: URL where the user completes authorization
- `verification_uri_complete`: Pre-filled URL including the user code

---

### 2. User Authorization

The user must complete the following steps:

1. Navigate to `verification_uri` (or use `verification_uri_complete`)
2. Enter the user_code (if not already included)
3. Log in or register with the Identity Provider
4. Grant consent to the aggregator

---
### 3. Finalizing Registration

While the user is completing authorization, your application should poll the registration endpoint using the `state`:

```http
POST /registration
Content-Type: application/json

{
  "registration_type": "device_code",
  "state": "<state>"
}

```

#### Possible Responses

⏳ **Pending**

```http
HTTP/1.1 202 Accepted
```

Returned when:
  - The user has not yet completed authorization
  - The aggregator is still being deployed

---

✅ **Success**

```http
HTTP/1.1 200 OK
Content-Type: application/json
{
  aggregator: <aggregator-base-iri>
}
```

Returns the location of the newly deployed aggregator.

---

❌ **Error**

```http
HTTP/1.1 400 Bad Request
```

## Authorization Code Flow

Under construction.

## Provision Flow

Under construction.