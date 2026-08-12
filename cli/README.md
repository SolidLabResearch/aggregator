# agg

A CLI tool for interacting with an Aggregator Server. It supports registering users via device flow, managing aggregators and services, and fetching service descriptions and dataset distributions.

## Installation

### Prerequisites

- Node.js 18+
- npm

### Install locally

```bash
npm run build
npm link
```

After linking, the `agg` command is available globally in your terminal.

## Configuration

Configuration is stored in a JSON file. The location is resolved in the following order:

1. `$AGG_CONFIG` — if this environment variable is set, it is used as the config file path
2. `$XDG_CONFIG_HOME/agg/config.json` — if `XDG_CONFIG_HOME` is set (Linux/macOS)
3. `~/.agg/config.json` — default fallback

To check where your config file is located:

```bash
agg where-config
```

To load an existing JSON file as your config:

```bash
agg set-config ./my-config.json
```

### Config structure

```json
{
  "activeAggregator": "https://aggregator.example.org/some-id",
  "aggregators": {
    "https://aggregator.example.org/some-id": {
      "id": "https://aggregator.example.org/some-id",
      "services": {
        "my-svc": {
          "name": "my-svc",
          "deploymentFunction": "fetch-profiled",
          "params": {
            "sources": "https://..."
          },
          "datasets": {
            "result": {
              "content": "https://aggregator.example.org/some-id/services/my-svc/content"
            }
          }
        }
      }
    }
  },
  "server": {
    "host": "https://aggregator.example.org",
    "deploymentCatalog": "/deployments",
    "svc": "/services",
    "reg": "/registration"
  },
  "auth": {
    "username": "user@example.org",
    "password": "password",
    "clientId": "my-client",
    "clientSecret": "my-secret",
    "idp": "https://idp.example.org",
    "uma": "https://uma.example.org"
  },
  "service": {
    "name": "my-svc",
    "deploymentFunction": "fetch-profiled",
    "params": {},
    "datasets": {}
  }
}
```

## Commands

### Authentication

#### `agg set-auth`

Set authentication configuration. All options are optional — only the provided values are updated.

```bash
agg set-auth --username user@example.org \
             --password secret \
             --client-id my-client \
             --client-secret my-secret \
             --idp https://idp.example.org \
             --uma https://uma.example.org
```

---

### Aggregator management

#### `agg register-user`

Register a user on the aggregator server using a device flow. Opens a browser URL for the user to authenticate, then polls for completion. On success, the aggregator is added to the config.

```bash
agg register-user                 # register and add aggregator to config
agg register-user --set-active    # also set it as the active aggregator
```

#### `list`

List all registered aggregators.

```bash
agg list
```

#### `agg set-active <id>`

Set the active aggregator by its ID.

```bash
agg set-active https://aggregator.example.org/some-id
```

#### `agg get-active`

Show the currently active aggregator and its registered services.

```bash
agg get-active
```

#### `agg reset`

Remove all aggregators and services from the config. Use when you removed the aggregator server.

```bash
agg reset
```

---

### Service management

#### `agg create-service`

Create a service on the active aggregator from a published deployment
function. On success, the service and its discovered distributions are stored
in the local CLI config.

```bash
agg create-service                                        # use config defaults
agg create-service --name my-svc --deployment-function fetch-profiled
agg create-service --param url=https://example.org/data   # repeatable
agg create-service --agg https://aggregator.example.org/other-id  # use specific aggregator
```

| Option | Description |
|---|---|
| `--name <name>` | Service name (overrides config) |
| `--deployment-function <id>` | Deployment function ID (overrides config) |
| `--param <key=value>` | Function parameter predicate and value; repeatable |
| `--agg <id>` | Aggregator ID to use instead of the active one |

Deployment function names are Kubernetes resource names, for example
`fetch-profiled`. A short parameter key such as `url` maps to the predicate of
the selected deployment document, for example
`https://aggregator.example.org/deployments/fetch-profiled#url`. An absolute
predicate URI is also accepted. The CLI loads the deployment document and uses
the declared `fno:type` to encode each value.

#### `agg get-service`

Fetch the description of a service from the active aggregator.

```bash
agg get-service
agg get-service --svc my-svc                              # specific service
agg get-service --agg https://aggregator.example.org/id  # specific aggregator
```

| Option | Description |
|---|---|
| `--svc <name>` | Service name (overrides active) |
| `--agg <id>` | Aggregator ID to use instead of the active one |

#### `agg delete-service`

Delete a deployed service and remove it from the local CLI configuration.

```bash
agg delete-service --name prepare-data
agg delete-service --name prepare-data --agg https://aggregator.example.org/id
```

| Option | Description |
|---|---|
| `--name <name>` | Service name (defaults to `service.name` from config) |
| `--agg <id>` | Aggregator ID to use instead of the active one |
| `--svc <name>` | Deprecated alias for `--name` |

#### `agg list-outputs`

List every dataset distribution available for a service. The output ID has the
form `dataset/distribution` and is followed by its resolved endpoint URL.

```bash
agg list-outputs
agg list-outputs --svc my-svc --agg <id>
```

| Option | Description |
|---|---|
| `--svc <name>` | Service name (overrides active) |
| `--agg <id>` | Aggregator ID to use instead of the active one |

#### `agg list-endpoints`

List every operational endpoint advertised by a service description. Endpoint
IDs are derived from the endpoint path relative to the service URL, for example
`/status` becomes `status` and `/session/start` becomes `session/start`.

```bash
agg list-endpoints
agg list-endpoints --svc prepare-data --agg <id>
```

| Option | Description |
|---|---|
| `--svc <name>` | Service name (overrides active) |
| `--agg <id>` | Aggregator ID to use instead of the active one |

#### `agg get-output <dataset/distribution>`

Fetch exactly one distribution using an ID reported by `list-outputs`. Dataset
and distribution URLs are discovered from the RDF returned when the service is
created; they are not supplied manually to the CLI.

```bash
agg get-output result/content
agg get-output result/content --svc my-svc --agg <id>
```

| Option | Description |
|---|---|
| `--svc <name>` | Service name (overrides active) |
| `--agg <id>` | Aggregator ID to use instead of the active one |

#### `agg get-endpoint <endpoint>`

Fetch exactly one operational endpoint using an ID reported by
`list-endpoints`. The CLI first loads the UMA-protected service description,
discovers the endpoint URL, and then performs a GET on that endpoint.

```bash
agg get-endpoint status
agg get-endpoint session/start --svc my-svc --agg <id>
```

| Option | Description |
|---|---|
| `--svc <name>` | Service name (overrides active) |
| `--agg <id>` | Aggregator ID to use instead of the active one |

#### `agg delete-service`

Delete a service from the active aggregator.

```bash
agg delete-service
agg delete-service --svc my-svc                              # specific service
agg delete-service --agg https://aggregator.example.org/id   # specific aggregator
```

| Option | Description |
|---|---|
| `--svc <name>` | Service name (overrides active) |
| `--agg <id>` | Aggregator ID to use instead of the active one |

---

### Access-role management

```bash
agg list-available-roles --svc weight-aggregation
agg list-active-roles --svc weight-aggregation
agg assign-role training-client https://example.org/participants/hospital-3 \
  --svc weight-aggregation
```

Available roles are discovered from the live service and profile RDF. Active
roles list the assignee and grant identifier. `assign-role` creates a simple
single-assignee ODRL Agreement; use the HTTP API for more complex templates.

All commands accept `--svc <name>` and `--agg <id>`.

---
agg get-service --svc my-svc                              # specific service
agg get-service --agg https://aggregator.example.org/id  # specific aggregator
```

| Option | Description |
|---|---|
| `--svc <name>` | Service name (overrides active) |
| `--agg <id>` | Aggregator ID to use instead of the active one |

---

### Config management

#### `agg set-config <file>`

Load a JSON file as the config, replacing the current config.

```bash
agg set-config ./my-config.json
```

#### `agg where-config`

Print the path to the current config file.

```bash
agg where-config
```
