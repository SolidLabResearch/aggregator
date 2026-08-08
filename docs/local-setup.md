# Local setup

This guide creates a local Kind cluster, builds the repository images, installs
Traefik, and deploys the Aggregator Platform.

## Prerequisites

Install Docker, Make, Kind, kubectl, Helm 3, OpenSSL, and mkcert. Node.js is
needed for the CLI and Go is needed to run the test suites directly.

## Configure Helm values

The default Makefile configuration is `config/local.yaml`. At minimum, set the
external host, ingress class, and an allowed registration flow:

```yaml
external:
  host: aggregator.local
  proto: http
  port: 5080

internal:
  serverPort: 5000
  serverInternalPort: 5001
  instancePort: 5000

auth:
  allowedRegistrationTypes:
    - none

ingressClassName: aggregator-traefik
tls:
  enabled: false
```

`internal.serverPort` is the server's cluster-facing HTTP listener and
`internal.serverInternalPort` is its private catalog listener. They are separate
from the externally published ingress ports under `external`.
`internal.instancePort` controls the HTTP listener, Service, Ingress backend,
and readiness probe of dynamically deployed aggregator instances.

For authenticated registration, replace `none` and configure one of the flows
documented in [Registering aggregators](deploying-aggregators.md). Provider
notes are available for [Community Solid Server](css-setup.md) and [Kvasir
Solid Server](kss-setup.md).

Do not commit real client secrets to the values files.

## Add deployment definitions

The Makefile automatically loads every values file below:

```text
config/profiles/*.yaml
config/deployment-functions/*.yaml
```

The included definitions provide profiled and unprofiled fetch examples plus a
profiled PACSOI deployment. See [Defining deployable
services](creating-services.md) before adding or changing definitions.

## Create and deploy

From the repository root:

```bash
make kind-init
make kind-deploy
```

`kind-init` creates or starts the `aggregator` Kind cluster, builds and loads
the container images, and installs Traefik. `kind-deploy` adds local host
entries and installs the chart with `config/local.yaml` plus all definition
files.

Verify the deployment:

```bash
kubectl -n aggregator-platform get pods
curl http://aggregator.local:5080/healthz
curl -H 'Accept: text/turtle' http://aggregator.local:5080/deployments
```

Use HTTPS and port `5443` instead when TLS is enabled.

## TLS

Generate a certificate for the local host:

```bash
mkcert -install
mkcert aggregator.local
```

Then configure:

```yaml
tls:
  enabled: true
  secretName: tls-secret
  mode: selfsigned
  selfSigned:
    crt: aggregator.crt
    key: aggregator.key
```

Node.js does not automatically trust the mkcert CA. Before using the CLI over
HTTPS, set:

```bash
export NODE_EXTRA_CA_CERTS="$(mkcert -CAROOT)/rootCA.pem"
```

## Local name resolution

`make kind-deploy` maps `aggregator.local` and `wsl.local` in the host file. If
workloads must reach another service running on the host, add its IP and name
to `kind/localhosts.yaml`, then run:

```bash
make configure-coredns
make configure-etc-hosts HOSTS="aggregator.local wsl.local <other-host>"
```

## Rebuild and test

```bash
make containers-all CONTAINER=aggregator-server
kubectl -n aggregator-platform rollout restart deployment/aggregator-server

make unit-test
make integration-test
```

Integration tests use the existing Kind cluster.

## Cleanup

```bash
make kind-undeploy  # remove the release and local host entries
make kind-delete    # delete the Kind cluster
```
