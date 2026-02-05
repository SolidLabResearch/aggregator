# Aggregator

[![Integration Tests](https://github.com/SolidLabResearch/aggregator/actions/workflows/integration-tests.yml/badge.svg)](https://github.com/SolidLabResearch/aggregator/actions/workflows/integration-tests.yml)

An aggregator using uma: https://github.com/SolidLabResearch/user-managed-access as the authorization server.

## Requirements

- helm

### Local setup

- kubectl
- kind (Kubernetes in Docker)
- make
- mkcert

## Quick Start

If you already have a cluster you can use the helm chart to deploy the aggregator-platform. For the full Helm configuration details see the [documentation](/aggregator-platform/README.md).

```bash
helm upgrade --install aggregator-platform ./aggregator-platform \
  -n aggregator-platform --create-namespace \
  --set host=aggregator.example.com \
  --set auth.allowedRegistrationTypes={none} \
  --set ingressClassName=<ingress-class-name> #traefik, nginx, ..
```

## API

The [demo](/docs/demo.md) walks through the API step by step.
All endpoints are relative to the aggregator base IRI:
```
http(s)://<host>
```
You can `GET` the base endpoint to retrieve the server’s specification and configuration.

---
### Registration Endpoint

Create an aggregator for a user.
Supported registration flows depend on the configured `allowedRegistrationTypes`.

Default endpoint:
```
POST http(s)://<host>/registration
```

---
### Transformation Catalog

Retrieve the list of available **FnO transformations** supported by the platform.

Default endpoint:
```
GET http(s)://<host>/transformations
```

---
### Aggregator Description

Retrieve the specification and configuration of a specific aggregator instance.

```
GET http(s)://<host>/<aggregator-id>
```

---
### Aggregator Service Collection

List services within an aggregator instance.

Default endpoint:
```
GET http(s)://<host>/<aggregator-id>/services
```

Create services within an aggregator instance.

Default endpoint:
```
POST http(s)://<host>/<aggregator-id>/services
```

---
### Aggregator Service

Retrieve the description of a specific service:

```
GET http(s)://<host>/<aggregator-id>/<service-id>
```

Retrieve the service outputs with corresponding output predicate:

```
GET http(s)://<host>/<aggregator-id>/<service-id>/<out-pred>
```

## Local Setup

### 1. Install Dependencies

**make**
```bash
sudo apt update
sudo apt install make
```

**kind:**
```bash
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind
```

**kubectl:**
```bash
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/
```

**helm:**
```bash
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```

**mkcert**
```bash
sudo apt update
sudo apt install mkcert libnss3-tools
```

### 2. Local cluster setup

#### 2.1 Create platform certificates

Run:
```bash
mkcert -install
mkcert aggregator.local
```

Node.js does not automatically trust the local Certificate Authority created by mkcert.
Set the `NODE_EXTRA_CA_CERTS` environment variable so Node (and fetch) trusts certificates signed by your mkcert CA.
```bash
export NODE_EXTRA_CA_CERTS="$(mkcert -CAROOT)/rootCA.pem"
```

#### 2.2 Create and Configure Kind Cluster

Run:
```bash
make kind-init
```

This will:
- Create local kind cluster
- Load containers into cluster
- Generate certificates and keys
- Start traefik ingress controller

#### 2.2 Configure Cluster DNS

Run:
```bash
make configure-coredns
```
This updates the cluster’s CoreDNS configuration.

When the aggregator runs inside the Kubernetes cluster, `localhost` refers to the container itself, not your machine. If the aggregator needs to call services running on your local machine (e.g. a UMA server), you must expose your host via custom DNS entries.

Example mappings:
```bash
<docker bridge ip> aggregator.host.local
<wsl ip> aggregator.wsl.local # If you are using WSL
```

#### Add or Modify DNS Entries
Edit [/kind/localhosts.yaml](/kind/localhosts.yaml) and apply:
```bash
make configure-coredns
```

#### Update Your Local Machine
For your local environment to resolve the same hostnames, you must also update `/etc/hosts`.

You can do this manually, or run:
```bash
make configure-etc-hosts HOSTS="aggregator.local aggregator.host.local aggregator.wsl.local"
```
If you use `make kind-deploy` / `make kind-undeploy`, update the `HOSTS` variable in the [makefile](/makefile) so this step runs automatically during deployment.

### 3. Deploy Aggregator Platform with Local Configuration

```bash
make kind-deploy
```

This will deploy the aggregator platform inside the local kind cluster using the [local setup helm values](kind/helm-config.yaml).

### 4. Stop/Clean-up

**Remove aggregator platform**
```bash
make kind-undeploy
```
**Start/stop cluster for resource saving**
```bash
make kind-stop        # Pause the cluster
make kind-start       # Start the paused cluster
```
**Remove cluster**
```bash
make kind-delete      # Delete cluster and host configuration
```

### 5. Interacting with the aggregator-platform

See [guide](/docs/demo.md) tailored to your local setup.

## Makefile Commands

### Cluster Management
```bash
make init          # Create cluster, build & load containers, start cleaner
make kind-start         # Create/start Kind cluster only
make kind-stop          # Pause Kind cluster
make kind-delete        # Delete Kind Cluster
make kind-dashboard     # Deploy Kubernetes dashboard
```

### Container Management
```bash
make containers-build              # Build all containers (parallel)
make containers-build CONTAINER=X  # Build specific container
make containers-load               # Load all images into Kind
make containers-load CONTAINER=X   # Load specific image
make containers-all                # Build and load all
make containers-all CONTAINER=X    # Build and load specific image
```

### Deployment
```bash
make deploy            # Deploy aggregator
make undeploy          # Remove aggregator
make kind-deploy       # Deploy aggregator + configure /etc/hosts
make kind-undeploy     # Remove aggregator + clean /etc/hosts
```

### Docker Cleanup
```bash
make docker-clean      # Clean up Docker images
```

### Testing
```bash
make integration-test  # Run full integration test suite
```

## Development Workflow

### Making Changes

```bash
# Rebuild specific container
make containers-build CONTAINER=aggregator-server
make containers-load CONTAINER=aggregator-server

# Restart deployment
make (kind-)undeploy
make (kind-)deploy
```

## Architecture

- **Kind Cluster**: Local Kubernetes cluster in Docker
- **Traefik**: Ingress controller (HTTP port 80)
- **Aggregator Server**: Registration and metadata service
- **Aggregator Cleaner**: Auto-cleanup controller for service namespaces
- **Dynamic Services**: Created per user in separate namespaces

## Ports

- **Port 80**: HTTP traffic to aggregator (via Traefik)
- **Port 443**: HTTPS traffic (available but not configured)

Access: `http://aggregator.local`

## Tests

Automated tests run on GitHub Actions for Linux on every push and pull request.

### Run Locally

Ensure Go is installed (required for running the tests):

```bash
sudo apt install -y golang-go
```

### Integration Tests

Integration tests use the existing Kind cluster created by `make init`.

```bash
# First-time setup
make init
make deploy

# Run tests (uses existing cluster)
make integration-test
```

The Integration tests will:
- deploy a test setup with mock OIDC and UMA servers
- Run all integration tests against `http://aggregator.local`
- Leave the cluster running after tests complete

### Unit Tests

Unit tests only test the functions so no cluster is needed.
The following make target will run all unit tests in all containers:

```bash
make unit-test
```

### CI/CD

The GitHub Actions workflow automatically:
1. Creates a test cluster
2. Builds and loads containers
3. Deploys Traefik and the aggregator
4. Runs the full test suite
5. Cleans up the test cluster

## Troubleshooting

### Cluster Issues

```bash
# Recreate cluster
make clean
make init
make deploy
```

### Container Build Failures

```bash
# Build specific container with verbose output
docker build containers/aggregator-server -t aggregator-server:latest

# Check logs
docker logs <container-id>
```

## Contributing

Integration tests run automatically on all pushes and pull requests.
Ensure tests pass before merging.

## License

See LICENSE file for details.
