# Deleting Services

This document will show how to delete a running Aggregator Service.

Deleting a service is done using the Service Description Endpoint advocated within the `service_collection`. The rest of this document assumes this endpoint is at `/services/del-example-svc`.

#### Request

To delete a Service, send a DELETE request to the Service Description Endpoint.

```http
DELETE /services/del-example-svc
```

This endpoint is UMA protected and needs the user to be authenticated with the `odrl:delete` scope.
