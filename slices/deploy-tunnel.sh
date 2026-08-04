#!/usr/bin/env bash

set -euo pipefail

SLICES_EXPERIMENT="${SLICES_EXPERIMENT:-aggregator-platform}"
SLICES_LAUNCHER="${SLICES_LAUNCHER:-kublauncher}"
SLICES_SSH_PROXY="${SLICES_SSH_PROXY:-auto}"
SLICES_CONTEXT="${SLICES_CONTEXT:-admin@aggregator-cluster}"
SLICES_CONTROL_PLANE="${SLICES_CONTROL_PLANE:-10.10.210.167}"
SLICES_API_TLS_NAME="${SLICES_API_TLS_NAME:-193.191.169.51}"
SLICES_LOCAL_PORT="${SLICES_LOCAL_PORT:-16443}"
RELEASE_NAMESPACE="${RELEASE_NAMESPACE:-aggregator-platform}"

TUNNEL_PID=""

cleanup() {
  if [[ -n "${TUNNEL_PID}" ]] && kill -0 "${TUNNEL_PID}" 2>/dev/null; then
    kill "${TUNNEL_PID}"
    wait "${TUNNEL_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

echo "Opening SSH tunnel to the Slices Kubernetes API..."
slices bi ssh "${SLICES_LAUNCHER}" \
  --experiment "${SLICES_EXPERIMENT}" \
  --proxy "${SLICES_SSH_PROXY}" \
  -N \
  -L "${SLICES_LOCAL_PORT}:${SLICES_CONTROL_PLANE}:6443" &
TUNNEL_PID=$!

for _ in {1..30}; do
  if nc -z 127.0.0.1 "${SLICES_LOCAL_PORT}" 2>/dev/null; then
    break
  fi

  if ! kill -0 "${TUNNEL_PID}" 2>/dev/null; then
    wait "${TUNNEL_PID}"
  fi

  sleep 1
done

if ! nc -z 127.0.0.1 "${SLICES_LOCAL_PORT}" 2>/dev/null; then
  echo "The SSH tunnel did not become ready on port ${SLICES_LOCAL_PORT}." >&2
  exit 1
fi

API_SERVER="https://127.0.0.1:${SLICES_LOCAL_PORT}"
VALUE_ARGS=(-f config/slices.yaml)

shopt -s nullglob
for value_file in config/profiles/*.yaml config/deployment-functions/*.yaml; do
  VALUE_ARGS+=(-f "${value_file}")
done

echo "Verifying access to the Slices cluster..."
kubectl \
  --context "${SLICES_CONTEXT}" \
  --server "${API_SERVER}" \
  --tls-server-name "${SLICES_API_TLS_NAME}" \
  get --raw=/version >/dev/null

echo "Deploying Aggregator Platform through the SSH tunnel..."
kubectl \
  --context "${SLICES_CONTEXT}" \
  --server "${API_SERVER}" \
  --tls-server-name "${SLICES_API_TLS_NAME}" \
  apply -f ./aggregator-platform/crds

helm upgrade --install aggregator-platform ./aggregator-platform \
  "${VALUE_ARGS[@]}" \
  --kube-context "${SLICES_CONTEXT}" \
  --kube-apiserver "${API_SERVER}" \
  --kube-tls-server-name "${SLICES_API_TLS_NAME}" \
  --namespace "${RELEASE_NAMESPACE}" \
  --create-namespace

kubectl \
  --context "${SLICES_CONTEXT}" \
  --server "${API_SERVER}" \
  --tls-server-name "${SLICES_API_TLS_NAME}" \
  rollout status deployment/aggregator-server \
  --namespace "${RELEASE_NAMESPACE}" \
  --timeout=120s

echo "Aggregator Platform successfully deployed to Slices."
