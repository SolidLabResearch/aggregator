### Support for multi-scope endpoints

an endpoint that sets inputs and then executes a function should expect scope odrl:execute and odrl:modify.

but ingress-uma does not parse the ticket correctly. It looks for one permission that contains both, but the ticket contains two permissions, one for each scope. So we need to add a new scope that is a combination of the two, and use that in the permission.

```json
{
  "permissions": [
    {
      "resource_id": "http://localhost:6004/alice/",
      "resource_scopes": [
        "urn:example:css:modes:create"
      ]
    },
    {
      "resource_id": "http://localhost:6004/alice/",
      "resource_scopes": [
        "http://example.com/test-scope"
      ]
    }
  ],
  "iat": 1786630707,
  "iss": "http://localhost:6104/uma",
  "aud": "solid",
  "exp": 1786631007,
  "jti": "f30271a6-484f-4c1f-a2a7-1f0d06c427f1"
}
```