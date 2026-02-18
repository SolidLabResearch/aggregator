#!/usr/bin/env bash
# cleanup-aggregator.sh
# Usage: ./cleanup-aggregator.sh <aggregator-id>

set -euo pipefail

AGGREGATOR_ID="${1:-}"
NAMESPACE="aggregator-platform-test"

if [[ -z "$AGGREGATOR_ID" ]]; then
  echo "Usage: $0 <aggregator-id>"
  exit 1
fi

echo "🧹 Cleaning up aggregator resources for ID: $AGGREGATOR_ID in namespace $NAMESPACE"

# 1️⃣ Delete all resources managed by this aggregator instance
echo "Deleting core workloads (deployments, pods, services, replicasets, statefulsets, daemonsets)..."
kubectl delete all \
  -n "$NAMESPACE" \
  -l "app.kubernetes.io/managed-by=${AGGREGATOR_ID}" \
  --ignore-not-found

echo "Deleting configmaps, secrets, PVCs..."
kubectl delete configmap,secret,pvc \
  -n "$NAMESPACE" \
  -l "app.kubernetes.io/managed-by=${AGGREGATOR_ID}" \
  --ignore-not-found

echo "Deleting ingresses..."
kubectl delete ingress \
  -n "$NAMESPACE" \
  -l "app.kubernetes.io/managed-by=${AGGREGATOR_ID}" \
  --ignore-not-found

echo "Deleting RBAC roles and rolebindings..."
kubectl delete role,rolebinding \
  -n "$NAMESPACE" \
  -l "app.kubernetes.io/managed-by=${AGGREGATOR_ID}" \
  --ignore-not-found

# 2️⃣ Delete aggregator deployments using the agg.knows.idlab.ugent.be/id label
echo "Deleting aggregator deployments by aggregator ID..."
kubectl delete all \
  -n "$NAMESPACE" \
  -l "agg.knows.idlab.ugent.be/id=${AGGREGATOR_ID}" \
  --ignore-not-found

echo "Deleting aggregator configmaps, secrets, PVCs by aggregator ID..."
kubectl delete configmap,secret,pvc \
  -n "$NAMESPACE" \
  -l "agg.knows.idlab.ugent.be/id=${AGGREGATOR_ID}" \
  --ignore-not-found

echo "Deleting aggregator ingresses by aggregator ID..."
kubectl delete ingress \
  -n "$NAMESPACE" \
  -l "agg.knows.idlab.ugent.be/id=${AGGREGATOR_ID}" \
  --ignore-not-found

echo "Deleting aggregator RBAC resources by aggregator ID..."
kubectl delete role,rolebinding \
  -n "$NAMESPACE" \
  -l "agg.knows.idlab.ugent.be/id=${AGGREGATOR_ID}" \
  --ignore-not-found

echo "✅ Cleanup complete for aggregator ID: $AGGREGATOR_ID"
