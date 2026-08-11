# Connecting to the Slices Kubernetes cluster

The Slices launcher exposes the internal Kubernetes API through an Nginx TCP
proxy:

```text
local kubectl -> 193.191.169.51:6443 -> Nginx on kublauncher
              -> 10.10.210.167:6443 -> Kubernetes API
```

Nginx restricts API access by source IP. There are two supported ways to deploy:

1. add the current public IPv4 address to the proxy allowlist; or
2. use an SSH tunnel as a temporary fallback.

Both approaches use `slices bi ssh` and leave the active kubectl context
unchanged.

## Prerequisites

- the Slices CLI is installed and authenticated;
- the current SSH public key is registered with Slices;
- `kubectl`, Helm 3, `curl`, and `nc` are installed; and
- the `admin@aggregator-cluster` context is present in the kubeconfig.

Register an SSH key when needed:

```sh
slices pubkey register ~/.ssh/id_ed25519.pub
```

Verify launcher access:

```sh
slices bi ssh kublauncher \
  --experiment aggregator-platform \
  --proxy auto
```

## Preferred: configure the public proxy

From the repository root:

```sh
./slices/configure-proxy.sh
```

The script:

- detects the current public IPv4 address using `ifconfig.me`;
- generates the complete Nginx stream configuration;
- keeps the existing UGent, Slices, and private-network allow rules;
- backs up the active launcher configuration;
- uploads the new configuration through `slices bi ssh`;
- applies backup, upload, validation, rollback, and reload through one SSH
  connection;
- validates it with `nginx -t`; and
- reloads Nginx only after successful validation.

Override detected or environment-specific values when necessary:

```sh
PUBLIC_IP=203.0.113.10 \
SLICES_CONTROL_PLANE=10.10.210.167 \
SLICES_WORKER=10.10.211.115 \
./slices/configure-proxy.sh
```

Both scripts default `SLICES_SSH_PROXY` to `auto`. The CLI uses a jump proxy
when the experiment provides one and otherwise connects directly:

```sh
SLICES_SSH_PROXY=on ./slices/configure-proxy.sh
```

The public IP may change when switching networks, connecting or disconnecting
a VPN, or receiving a new address from an ISP. WSL's local `172.x.x.x` address
is not the address seen by the launcher and must not be allowlisted.

Verify access:

```sh
kubectl --context admin@aggregator-cluster get nodes
```

Deploy after verification:

```sh
make slices-deploy
```

## Install or refresh the kubeconfig

Obtain the launcher connection details:

```sh
slices bi ssh kublauncher \
  --experiment aggregator-platform \
  --proxy auto \
  --show command
```

Copy `~/.kube/config` from the launcher using the displayed SSH connection and
save it locally as `~/.kube/slices-config`. Confirm that its server is:

```text
https://193.191.169.51:6443
```

Merge it without discarding existing contexts:

```sh
KUBECONFIG=~/.kube/config:~/.kube/slices-config \
  kubectl config view --flatten > ~/.kube/merged
mv ~/.kube/merged ~/.kube/config
```

Verify the named context without changing the active context:

```sh
kubectl --context admin@aggregator-cluster get nodes
```
