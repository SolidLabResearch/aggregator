# Deleting Aggregator Instances

This document will show how to delete a running Aggregator.

Deleting an aggregator is done using the endpoint advocated with `registration_endpoint` at the discovery endpoint. The rest of this document assumes this endpoint is at `/registration`.

#### Request

To delete an Aggregator, send a DELETE request to the registration endpoint including the Aggregator ID.

```http
DELETE /registration
Content-Type: application/json

{
  "aggregator_id": "<Aggregator ID>"
}
```

If the Aggregator was deployed using an Authentication flow, the request should contain an `Authorization` Header
with an ID Token identifying the Aggregator owner.

[!WARNING]
The current implementation expects the client to be able to get a valid ID Token from the Aggregator IDP. This is not always
the case. This issue will be handled in later versions.

#### Possible Responses

✅ **Success**

```http
HTTP/1.1 204 No Content
```

Returned when the Aggregator was succesfully deleted.

---

🔒 **Unauthorized**

```http
HTTP/1.1 401 Unauthorized
```

Returned when missing an `Authorization` Header or providing invalid credentials

---

❌ **Forbidden**

```http
HTTP/1.1 400 Bad Request
```

Returned when the authenticated user does not have ownership over the Aggregator

