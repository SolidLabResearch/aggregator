# Aggregator

[![Integration Tests](https://github.com/SolidLabResearch/aggregator/actions/workflows/integration-tests.yml/badge.svg)](https://github.com/SolidLabResearch/aggregator/actions/workflows/integration-tests.yml)

Aggregator deploys isolated data-processing services in Kubernetes and protects
their APIs with User-Managed Access (UMA). An Aggregator Server registers and
manages per-user aggregator instances; each instance can deploy workloads from
the server's catalog of `DeploymentFunction` and `Profile` resources.

## Start locally

Prerequisites and configuration are covered in the [local setup
guide](docs/local-setup.md). The normal workflow is:

```bash
make kind-init
make kind-deploy
make integration-test
```

For an existing Kubernetes cluster, configure `config/local.yaml` or another
Helm values file and run:

```bash
make deploy CONFIG=my-values.yaml
```

`make deploy` installs the chart, the current CRDs, and all definition files in
`config/profiles/` and `config/deployment-functions/`.

## Public API

All paths are relative to `http(s)://<host>`:

| Method and path | Purpose |
| --- | --- |
| `GET /` | Server specification and configuration |
| `POST /registration` | Register an aggregator instance |
| `GET /profiles[/{name}]` | List or retrieve semantic profiles |
| `GET /deployments[/{name}]` | List or retrieve deployment functions |
| `GET /<aggregator-id>` | Describe an aggregator instance |
| `GET, POST /<aggregator-id>/services` | List or create services |
| `GET, HEAD, DELETE /<aggregator-id>/services/<name>` | Inspect or delete a service |

Service descriptions advertise resolved dataset distribution URLs. Clients
should follow those `dcat:accessURL` or `dcat:downloadURL` values instead of
constructing output URLs.

## Documentation

- [Local development and deployment](docs/local-setup.md)
- [Helm chart reference](aggregator-platform/README.md)
- [Defining deployable services](docs/creating-services.md)
- [Deployment definitions and profiles](docs/deployment-definitions.md)
- [Registering aggregators](docs/deploying-aggregators.md)
- [Deploying and accessing services](docs/deploying-services.md)
- [PACSOI example](docs/pacsoi-example.md)
- [CLI reference](cli/README.md)
- [UMA policies](docs/uma-policies.md)
- [Slices cluster access](slices/docs/kubectl.md)
- [Adding Slices worker nodes](slices/docs/workers.md)

The CSS and KSS documents describe identity-provider-specific setup and are
only needed when using those environments.

## Common commands

```bash
# Cluster
make kind-init
make kind-start
make kind-stop
make kind-delete

# Images
make containers-build
make containers-load
make containers-all CONTAINER=fetch

# Deploy or remove
make deploy CONFIG=my-values.yaml
make undeploy
make kind-deploy
make kind-undeploy
make slices-deploy
make slices-undeploy

# Tests
make unit-test
make integration-test
```

Automated tests run on Linux for every push and pull request.
