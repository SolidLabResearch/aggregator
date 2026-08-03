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
          "deploymentFunction": "DeployExample",
          "params": {
            "sources": "https://..."
          },
          "datasets": {
            "result": "/result"
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
    "deploymentFunction": "DeployExample",
    "params": {},
    "datasets": {
      "result": "/result"
    }
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

Create a service on the active aggregator using the service configuration. On success, the service is added to the aggregator's service list in the config.

```bash
agg create-service                                        # use config defaults
agg create-service --name my-svc --deployment-function DeployExample
agg create-service --param sources=https://... \
                   --param weight-slice=abc               # override params (repeatable)
agg create-service --dataset result=/result               # override datasets
agg create-service --agg https://aggregator.example.org/other-id  # use specific aggregator
```

| Option | Description |
|---|---|
| `--name <name>` | Service name (overrides config) |
| `--deployment-function <id>` | Deployment function ID (overrides config) |
| `--dataset <id=path>` | Dataset distribution access path; repeatable |
| `--param <key=value>` | Function parameter predicate and value; repeatable |
| `--agg <id>` | Aggregator ID to use instead of the active one |

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

#### `agg get-dataset`

Fetch dataset distributions from the active aggregator. By default it fetches every dataset configured for the service. `get-output` remains an alias.

```bash
agg get-dataset                                  # fetch all datasets
agg get-dataset --datasets result                # fetch a subset
agg get-dataset --svc my-svc --agg <id>          # specific service and aggregator
```

| Option | Description |
|---|---|
| `--datasets <ids>` | Comma-separated subset of dataset IDs to fetch |
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
