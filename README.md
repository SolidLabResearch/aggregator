# Aggregator

[![Integration Tests](https://github.com/SolidLabResearch/aggregator/actions/workflows/integration-tests.yml/badge.svg)](https://github.com/SolidLabResearch/aggregator/actions/workflows/integration-tests.yml)

An aggregator using uma: https://github.com/SolidLabResearch/user-managed-access as the authorization server.

## Requirements

- Docker
- Kubernetes cluster
- Helm

### Local setup
- Kind (Kubernetes in Docker)
- Make
- mkcert

## Quick Start
**Production Cluster**

```bash
make deploy CONFIG=<helm config file>
```
or use Helm directly:
```bash
helm upgrade --install aggregator-platform ./aggregator-platform \
  -n aggregator-platform --create-namespace \
  --set host=aggregator.example.com \
  --set auth.server=https:exaple.auth.com \
  --set auth.clientId=aggregator-id \
  --set auth.clientSecret=aggregator-secret \
  --set auth.allowedRegistrationTypes={device_code} \
```
For the full Helm configuration details see [documentation](/aggregator-platform/README.md)

**Local development**

```bash
# Full setup: Create cluster, build containers, deploy everything
make kind-init
make configure-etc-hosts HOSTS="aggregator.local"
make configure-coredns
make kind-deploy
```

## Local Setup

### 1. Install Dependencies

**Kind:**
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

**Helm:**
```bash
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```

### 2. Local cluster setup

#### 2.1 Create platform certificates

```bash
mkcert -install
mkcert aggregator.local
# Nodejs fetch will trust the local CA root
export NODE_EXTRA_CA_CERTS="$(mkcert -CAROOT)/rootCA.pem"
```

#### 2.2 Create and Configure Kind Cluster

```bash
make kind-init
```

This will:
- Create local kind cluster
- Load containers into cluster
- Generate certificates and keys
- Start traefik ingress controller

#### 2.2 Configure hosts and DNS (localhost access)

Configure cluster DNS so it can reach your localhost. Add entries to [/kind/coredns/local-hosts.yaml](/kind/coredns/local-hosts.yaml) and apply:
```bash
make configure-coredns
```

To reach the aggregator-platform and work with cluster DNS entries update /etc/hosts:
```bash
make configure-etc-hosts HOSTS="aggregator.local test.local"
```

### 3. Deploy aggregator platform with local configuration

```bash
make kind-deploy
```

This will deploy the aggregator platform inside the local kind cluster using the [local setup helm values](kind/helm-config.yaml)

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

**Clean /etc/hosts**
```bash
make clean-etc-hosts
```

## Makefile Commands

### Cluster Management
```bash
make init          # Create cluster, build & load containers, start cleaner
make kind-start         # Create/start Kind cluster only
make kind-stop          # Delete Kind cluster
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
make deploy            # Deploy Traefik + aggregator
make kind-deploy       # Deploy aggregator only
make kind-undeploy     # Remove aggregator (keep Traefik & cleaner)
make stop              # Stop aggregator + Traefik (keep cluster & cleaner)
```

### Cleanup
```bash
make stop              # Stop services (cluster stays alive)
make kind-clean        # Remove all deployments (cluster stays alive)
make clean             # Delete everything including cluster
make docker-clean      # Clean up Docker images
```

### Testing
```bash
make integration-test  # Run full integration test suite
```

### Utilities
```bash
make hosts-add         # Add aggregator.local to /etc/hosts
make hosts-remove      # Remove aggregator.local from /etc/hosts
make enable-wsl        # Configure CoreDNS for WSL2
```

## Development Workflow

### Making Changes

```bash
# Rebuild specific container
make containers-build CONTAINER=aggregator-server
make containers-load CONTAINER=aggregator-server

# Restart deployment
kubectl rollout restart deployment aggregator-server -n aggregator-app

# Or rebuild everything
make stop
make containers-all
make deploy
```

### Quick Iteration

```bash
# After code changes
make stop              # Stop current deployment
make containers-all    # Rebuild & reload
make deploy            # Redeploy
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
