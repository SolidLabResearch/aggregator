#!/usr/bin/env bash

set -euo pipefail

NAMESPACE="${1:-default}"
LOG_DIR="./logs"
INTERVAL=5

mkdir -p "$LOG_DIR"

echo "Watching namespace: $NAMESPACE"
echo "Logs directory: $LOG_DIR"

declare -A POD_PIDS

start_logging() {
    local pod="$1"

    # Skip if already logging
    if [[ -n "${POD_PIDS[$pod]:-}" ]]; then
        return
    fi

    echo "Starting logs for pod: $pod"

    kubectl logs -n "$NAMESPACE" -f "$pod" \
        > "$LOG_DIR/${pod}.log" 2>&1 &

    POD_PIDS[$pod]=$!
}

stop_logging() {
    local pod="$1"

    if [[ -n "${POD_PIDS[$pod]:-}" ]]; then
        echo "Stopping logs for pod: $pod"
        kill "${POD_PIDS[$pod]}" 2>/dev/null || true
        unset POD_PIDS[$pod]
    fi
}

while true; do
    # Get current pods
    current_pods=$(kubectl get pods -n "$NAMESPACE" \
        -o jsonpath='{.items[*].metadata.name}')

    # Start logging for new pods
    for pod in $current_pods; do
        start_logging "$pod"
    done

    # Stop logging for deleted pods
    for pod in "${!POD_PIDS[@]}"; do
        if ! grep -qw "$pod" <<< "$current_pods"; then
            stop_logging "$pod"
        fi
    done

    sleep "$INTERVAL"
done
