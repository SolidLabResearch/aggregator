# Aggregator

[![Integration Tests](https://github.com/SolidLabResearch/aggregator/actions/workflows/integration-tests.yml/badge.svg)](https://github.com/SolidLabResearch/aggregator/actions/workflows/integration-tests.yml)

An aggregator using uma: https://github.com/SolidLabResearch/user-managed-access as the authorization server.

## Quick Start

If you already have a cluster you can use the helm chart to deploy the aggregator-platform. For the full Helm configuration details see the [documentation](/aggregator-platform/README.md).

```bash
helm upgrade --install aggregator-platform ./aggregator-platform \
  -n aggregator-platform --create-namespace \
  --set host=aggregator.example.com \
  --set auth.allowedRegistrationTypes={none} \
  --set ingressClassName=<ingress-class-name> #traefik, nginx, ..
```

To start with a local setup, follow the instruction in the [Local Setup Guide](/docs/local-setup.md).

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

More on registration flows in the [documentation](/docs/deploying-aggregators.md)

---
### Transformation Catalog

Retrieve the list of available **FnO transformations** supported by the platform.

Default endpoint:
```
GET http(s)://<host>/transformations
```

More on transformations in the [documentation](/docs/creating-services.md)

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

Deploy services within an aggregator instance.

Default endpoint:
```
POST http(s)://<host>/<aggregator-id>/services
```

More on deploying services in the [documentation](/docs/deploying-services.md)

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

More on accessing services in the [documentation](/docs/deploying-services.md)

## Makefile Commands

### Cluster Management
```bash
make kind-init          # Create cluster, build & load containers, start cleaner
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

## Tests

Automated tests run on GitHub Actions for Linux on every push and pull request.

### Run Locally

Ensure Go is installed (required for running the tests):

```bash
sudo apt install -y golang-go
```

### Integration Tests

Integration tests use the existing Kind cluster created by `make kind-init`.

```bash
# First-time setup
make kind-init

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
