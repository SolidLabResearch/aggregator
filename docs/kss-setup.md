# Setup with KSS

Follow these steps to set up the aggregator using the Kvasir Solid Server and Solid UMA Server.

## Setting up a Solid UMA Server

If you already have a running Solid UMA server, you can skip this part.

We will use the UMA for Solid implementation. Clone the following repository:

```bash
git clone https://github.com/SolidLabResearch/user-managed-access
```

For this setup, we only need the `uma` package. Use the following dockerfile to create an image:

```dockerfile
FROM node:22
ENV NODE_ENV=production

# Install EYE reasoner
RUN apt-get update  \
 && apt-get install swi-prolog -y \
 && git clone https://github.com/eyereasoner/eye.git \
 && /eye/install.sh --prefix=/usr/local \
 && rm -r /eye

WORKDIR /usr/src/app
COPY . .

# Install packages and build server
RUN corepack enable yarn \
 && yarn install \
 && yarn build \
 && chown -R node /usr/src/app

# Set working directory to UMA package
WORKDIR /usr/src/app/packages/uma

EXPOSE 4000

USER node

CMD ["yarn", "start"]
```

Run the image using `--network host`. This ensure the UMA Server will be reachable by `localhost`, as well as the aggregator server running in the kind cluster.

```bash
docker run --network host uma:latest
```

### Registering the KSS as Resource Server

Before setting up the KSS, you must register credentials for it (see [UMA Documentation](https://github.com/SolidLabResearch/user-managed-access/blob/main/documentation/getting-started.md#authenticating-as-resource-server)). The following [demo script](/demo/kvasir/get-credentials.ts) registers and prints the credentials. Make sure to set the following constants:

- `UMA_SERVER` to your running Solid UMA Server
- `KVASIR_SERVER` to the adress where the KSS will be hosted

## Setting up a Kvasir Server

Follow [these](https://kvasir.pages.ilabt.imec.be/kvasir-server/getting-started.html#running-with-compose) steps to set up the server using docker compose.

Before starting the server you can [configure](https://kvasir.pages.ilabt.imec.be/kvasir-server/pod-management.html#pod-configuration) some initial pods.

Do not forget to register the UMA Server credentials (see [UMA Pod Configuration](https://kvasir.pages.ilabt.imec.be/kvasir-server/pod-management.html#uma-configuration))!

You now have a running Kvasir Server with one or more pods.

## Setting up Keycloak

Register two clients in Keycloak:

- **Aggregator Server Client** — used by the aggregator server to authenticate and manage aggregators.
  - Confidential client with Service Account Roles enabled
- **Demo Client** — used to interact with the aggregator and UMA server.
  - Confidential client with Direct Access Grants enabled (if no UI)
  - Public client (if there is a UI)

Both must support atleast the `openid` and `offline_access` scopes.

### Aggregator Server Client

#### Service Account Roles

The aggregator server authenticates using its own client credentials, so **Service Account Roles** must be enabled.

#### Registration Flow

When a server deploys an aggregator, it must obtain a refresh token that identifies the aggregator's owner. This is done through a registration flow. Two flows are supported — the client must be configured to support at least one:

| Flow | Required Grant Type |
|---|---|
| `device_code` | Device Authorization Grant |
| `token_exchange` | Token Exchange |

#### Token Exchange (additional setup)

When using `token_exchange`, two extra steps are required:

1. **Enable refresh tokens for client credentials grant** — the aggregator client must have *"Use Refresh Tokens For Client Credentials Grant"* enabled:
   > Clients → `agg-client` → Advanced → OpenID Connect Compatibility Modes

2. **Add the aggregator client to the Demo Client's token audience** — the access token issued to the Demo Client must include the aggregator server client ID in its `aud` claim, otherwise Keycloak will reject the exchange:
   > Clients → `demo-client` → Client scopes → `<aggregator aud scope>` → Add mapper → Audience → set *Included Client Audience* to the aggregator server client ID

## Configure a Kvasir Pod

### Delegating access control to UMA

Make sure the Pod is configured to delegate access to the UMA Server (see [UMA Access Control Delegation](https://kvasir.pages.ilabt.imec.be/kvasir-server/access-control.html#a4ds-uma-2-0-authorization-servers)).

This is an example request that delegates the whole `alice` pod to UMA, so even creating and deleting slices will require UMA policies:

```
{
  "@context": {
    "kss": "https://kvasir.discover.ilabt.imec.be/vocab#",
    "kss-fga": "https://kvasir.discover.ilabt.imec.be/fine-grained-access#"
  },
  "kss:insert": [
    {
      "@id": "urn:kvasir-wildcard",
      "@type": "kss-fga:User",
      "kss-fga:owner": {
        "@id": "http://localhost:8080/alice/",
        "@type": "kss-fga:Resource",
        "kss-fga:external_access": {
          "@id": "kss-fga:Uma"
        }
      }
    }
  ]
}
```

### Set up Pod Policies

When adding a policy you must add a keycloak bearer access token for the assigner ID to the `Authorization` header. 

The UMA server needs the following policies if the pod owner wants to interact with the pod:

  - Policy to create/delete slices:
    - scopes: `read`, `write`, `delete`
    - target: `<pod url>/slices`
    - assigner: `http://example.com/id/<owner id>`
    - assignee: `http://example.com/id/<owner id>`
    - client constraint: `http://example.com/id/<demo client id>`
  
  - Policy for each created slice:
    - If adding data via `mutation`:
      - scopes: `read`, `write`
      - target: `<pod url>/slices/<slice id>/query`
      - assigner: `http://example.com/id/<owner id>`
      - assignee: `http://example.com/id/<owner id>`
      - client constraint: `http://example.com/id/<demo client id>`
    - If adding data via `changes` API:
      - scopes: `read`, `write`
      - target: `<pod url>/slices/<slice id>/changes`
      - assigner: `http://example.com/id/<owner id>`
      - assignee: `http://example.com/id/<owner id>`
      - client constraint: `http://example.com/id/<demo client id>`
    - If the aggregator needs access to the slice:
      - use `http://example.com/id/<aggregator server id>` for the client constraint

## Setting up the Aggregator Server Authentication

You need the following authentication configuration in the helm file:

```yaml
auth:
  oidc:
    clientId: <aggregator server id>
    server: <keycloak realm url>
    clientSecret: <aggregator server secret>
  allowedRegistrationTypes:
    - device_code
    - token_exchange
```