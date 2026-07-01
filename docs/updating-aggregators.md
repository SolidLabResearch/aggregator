# Updating Aggregators

Aggregators authenticate on behalf of a user using a long-lived refresh token obtained during registration. These refresh tokens do not last indefinitely — they expire based on the Identity Provider's session and token lifetime policies.

When a refresh token expires, the aggregator can no longer act on behalf of the user and must be updated to issue a new one.

## Update Flow

To update an existing aggregator, repeat any registration flow as defined in [Deploying Aggregators](deploying-aggregators.md), adding the `aggregator_id` of the aggregator to update:

```http
POST /registration
Content-Type: application/json

{
  "registration_type": "<device_code | token_exchange>",
  "aggregator_id": "<aggregator-id>"
}
```

The aggregator server will verify that the authenticated user owns the specified aggregator before issuing a new refresh token.

### Additional Responses

In addition to the standard responses described in [Deploying Aggregators](deploying-aggregators.md), the following responses may be returned:

❌ **403 Forbidden**

Returned if the authenticated user does not own the specified aggregator.

❌ **404 Not Found**

Returned if the specified `aggregator_id` does not exist.