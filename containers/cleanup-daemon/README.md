# Cleanup Daemon

A Kubernetes service that handles graceful cleanup of pods and services when the aggregator shuts down.

## Overview

This daemon runs as a separate pod in the cluster and provides an HTTP endpoint for triggering cleanup operations. When the main aggregator receives a shutdown signal, it calls this daemon instead of performing cleanup inline, preventing incomplete cleanup due to termination grace period expiration.

## Building

The cleanup daemon is built automatically with other containers:

```bash
# Build all containers including cleanup-daemon
make containers-build

# Or build just cleanup-daemon
make containers-build name=cleanup-daemon
```

## Deployment

Deploy with the provided Kubernetes manifest from the root directory:

```bash
kubectl apply -f cleanup-daemon.yaml
```

The manifest includes:
- ServiceAccount with RBAC permissions
- Service for internal cluster access
- Deployment with 1 replica

## API

### `GET /health`
Health check endpoint for liveness/readiness probes.

**Response:** `200 OK` with body `"OK"`

### `POST /cleanup`
Triggers cleanup of all pods and services in the namespace.

**Response:** `202 Accepted` - cleanup starts in background

**Actions:**
1. Lists and deletes all pods (3 retry attempts with 5s between)
2. Lists and deletes all services (except `kubernetes` and `cleanup-daemon`)
3. Exits after 5 seconds

## Environment Variables

- `NAMESPACE` - Kubernetes namespace to clean (default: `default`)
- `PORT` - HTTP server port (default: `9999`)
- `LOG_LEVEL` - Logging level: debug, info, warn, error (default: `info`)

## Usage from Main Aggregator

The main aggregator automatically calls the cleanup daemon on shutdown:

```go
cleanupURL := "http://cleanup-daemon.default.svc.cluster.local:9999/cleanup"
resp, err := http.Post(cleanupURL, "", nil)
// Falls back to inline cleanup if daemon unreachable
```

## Monitoring

View logs:
```bash
kubectl logs -f -l app=cleanup-daemon
```

Expected output:
```
🚀 Starting cleanup daemon namespace=default port=9999
🧹 Cleanup daemon listening port=9999
🧹 Cleanup requested - starting resource deletion
🧹 Deleting pods...
Deleting pods count=19 attempt=1
✅ All pods deleted
🧹 Deleting services...
✅ All services deleted
✅ Cleanup complete - daemon will exit in 5 seconds
```

