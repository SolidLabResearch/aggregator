#!/usr/bin/env bash

set -euo pipefail

SLICES_EXPERIMENT="${SLICES_EXPERIMENT:-aggregator-platform}"
SLICES_LAUNCHER="${SLICES_LAUNCHER:-kublauncher}"
SLICES_SSH_PROXY="${SLICES_SSH_PROXY:-auto}"
SLICES_CONTROL_PLANE="${SLICES_CONTROL_PLANE:-10.10.210.167}"
SLICES_WORKER="${SLICES_WORKER:-10.10.211.115}"
PUBLIC_IP="${PUBLIC_IP:-}"

if [[ -z "${PUBLIC_IP}" ]]; then
  PUBLIC_IP="$(curl --fail --silent --show-error --ipv4 https://ifconfig.me)"
fi

if [[ ! "${PUBLIC_IP}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "Could not determine a valid public IPv4 address: ${PUBLIC_IP}" >&2
  exit 1
fi

PROXY_CONFIG="$(mktemp)"
cleanup() {
  rm -f "${PROXY_CONFIG}"
}
trap cleanup EXIT INT TERM

cat >"${PROXY_CONFIG}" <<EOF
stream {
    upstream kubernetes_api {
        server ${SLICES_CONTROL_PLANE}:6443;
    }

    server {
        listen 6443;
        proxy_pass kubernetes_api;
        proxy_timeout 10m;
        proxy_connect_timeout 1s;

        allow ${PUBLIC_IP}/32;
        allow 157.193.0.0/16;
        allow 193.191.169.0/24;
        allow 10.0.0.0/8;
        deny all;
    }

    upstream traefik_http {
        server ${SLICES_CONTROL_PLANE}:30080;
        server ${SLICES_WORKER}:30080;
    }

    server {
        listen 5000;
        proxy_pass traefik_http;
        proxy_timeout 10m;
        proxy_connect_timeout 1s;
        allow all;
    }

    server {
        listen 6000;
        proxy_pass traefik_http;
        proxy_timeout 10m;
        proxy_connect_timeout 1s;
        allow all;
    }
}
EOF

REMOTE_CONFIG="/etc/nginx/modules-enabled/kubernetes.conf"
REMOTE_BACKUP="${REMOTE_CONFIG}.bak"

echo "Allowing ${PUBLIC_IP}/32 through the Slices Kubernetes API proxy..."

slices bi ssh "${SLICES_LAUNCHER}" \
  --experiment "${SLICES_EXPERIMENT}" \
  --proxy "${SLICES_SSH_PROXY}" \
  "set -e;
   sudo cp ${REMOTE_CONFIG} ${REMOTE_BACKUP} 2>/dev/null || true;
   sudo tee ${REMOTE_CONFIG} >/dev/null;
   if sudo nginx -t; then
     sudo systemctl reload nginx;
   else
     echo 'Nginx validation failed; restoring the previous configuration.' >&2;
     sudo test -f ${REMOTE_BACKUP} && sudo cp ${REMOTE_BACKUP} ${REMOTE_CONFIG};
     exit 1;
   fi" <"${PROXY_CONFIG}"

echo "Slices proxy configured successfully."
echo "Verify access with:"
echo "  kubectl --context admin@aggregator-cluster get nodes"
