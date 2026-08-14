# PACSOI setup guide

This guide explains how to configure this repository, access the PACSOI
Slices cluster, deploy the Aggregator Server, and create a personal aggregator.

You should have received a ZIP archive containing:

- `cli-config-slices.json`;
- `slices.yaml`; and
- a `slices/` directory containing the cluster configuration, dashboard token,
  and other Slices deployment files.

These files can contain credentials or other sensitive configuration. Keep the
ZIP and extracted files private, and do not commit them to Git.

## 1. Put the supplied files in the repository

Extract the ZIP archive and copy its contents into a checkout of this
repository so that the resulting layout is:

```text
aggregator/
├── cli-config-slices.json
├── config/
│   └── slices.yaml
└── slices/
    ├── dashboard/
    │   └── token.txt
    ├── docs/
    └── ...other supplied Slices files...
```

Merge the supplied `slices/` directory into the existing repository `slices/`
directory; do not place it inside that directory as a second nested
`slices/slices/` directory.

Each supplied item has a different purpose:

| Item | Destination | Purpose |
| --- | --- | --- |
| `cli-config-slices.json` | Repository root | Configures the `agg` CLI with the PACSOI Aggregator Server and authentication settings used to create and manage aggregators. |
| `slices.yaml` | `config/slices.yaml` | Helm values for the Aggregator Server running in the Slices cluster, including its public address, authentication, images, ingress, and related server settings. `make slices-deploy` reads this file. |
| Contents of the supplied `slices/` directory | Merge into the repository's `slices/` directory | Contains PACSOI cluster-access and operational material, such as the Kubernetes cluster configuration, dashboard token, and deployment helpers. |

### Update the aggregator server configuration

Update the`slices.yaml` authorization settings under `auth`. When a new kvasir deployments is created, credentials (and URLS) might be deprecated. Create a new (confidential) aggregator client and update the `clientId` and `clientSecret` values in `slices.yaml`. The `issuer` URL should also be updated if the authorization server changes. Make sure the client is configured to allow Service Accounts and the Device Code Flow. Ask the Kvasir team for help.

## 2. Configure access to the Slices cluster

Follow the complete [Slices Kubernetes access guide](kubectl.md). It explains
the required tools, Slices authentication, SSH-key registration, kubeconfig
installation, and public proxy configuration.

In summary:

1. Install and authenticate the Slices CLI, and register your SSH public key.
2. Install or merge the supplied cluster configuration into your local
   kubeconfig as described in the access guide.
3. From the repository root, allow your current public IP through the cluster
   proxy:

   ```bash
   ./slices/configure-proxy.sh
   ```

4. Verify access without changing your active Kubernetes context:

   ```bash
   kubectl --context admin@aggregator-cluster get nodes
   ```

If your public IP changes, run `./slices/configure-proxy.sh` again.

## 3. Deploy or update the Aggregator Server

If there is already a running Aggregator Server, undeploy it first:

```bash
make slices-undeploy
```

After cluster access works and `config/slices.yaml` is in place, deploy the
server from the repository root:

```bash
make slices-deploy
```

This installs or upgrades the Aggregator Platform in the Slices cluster using
the supplied PACSOI server configuration. It also waits for the Aggregator
Server deployment to become ready.

## 4. Use the Kubernetes dashboard

Open the [PACSOI Kubernetes dashboard](https://dashboard.aggregator.pacsoi.knows.idlab.ugent.be/).
Choose token authentication and paste the token stored at:

```text
slices/dashboard/token.txt
```

The dashboard provides a graphical view of the cluster's namespaces,
deployments, pods, services, and logs. Treat the token like a password and do
not share or commit it.

## 5. Install the Aggregator CLI

The CLI requires Node.js 18 or newer and npm. From the repository root, run:

```bash
cd cli
npm ci
npm run build
npm link
cd ..
```

`npm link` makes the `agg` command available globally for the current Node.js
installation. Confirm the installation with:

```bash
agg --help
```

## 6. Load the supplied CLI configuration

From the repository root, load the configuration from the ZIP:

```bash
agg set-config ./cli-config-slices.json
```

The command copies the supplied settings into the CLI's active configuration
file. To see the active file location, run:

```bash
agg where-config
```

Keep `cli-config-slices.json` in the repository root as the supplied source
configuration, but continue to keep it out of Git because it may contain
credentials.

## 7. Create and register an aggregator

Once the Aggregator Server is running and the CLI configuration is loaded,
start registration:

```bash
agg register-user
```

The CLI starts a device-login flow and displays a URL. Open that URL, log in,
and complete authorization. The CLI waits for the server to create your
aggregator and then prints and stores its aggregator base URL. With
`--set-active`, the new aggregator also becomes the default for later CLI
commands.

Confirm the active aggregator with:

```bash
agg get-active
```

Copy the resulting aggregator base URL into `aggregator-config.json` in the
PACSOI orchestration repository. Use the base URL exactly as returned by the
CLI; do not append a service or output path.

For all CLI commands, configuration details, service creation, output access,
and aggregator management, see the full [Aggregator CLI reference](../../cli/README.md).
