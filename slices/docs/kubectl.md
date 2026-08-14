# Connect to the Slices Kubernetes cluster

This guide configures local `kubectl` access to the PACSOI Slices cluster. It
uses the `admin@aggregator-cluster` context explicitly, so following the guide
does not change the active context used for other Kubernetes clusters.

The normal connection path is:

```text
local kubectl -> 193.191.169.51:6443 -> Nginx on kublauncher
              -> 10.10.210.167:6443 -> Kubernetes API
```

The launcher proxy only accepts allowlisted source IP addresses. Initial setup
therefore consists of installing the kubeconfig and adding your current public
IP to the proxy.

## Prerequisites

Install the following tools before continuing:

- the Slices CLI, authenticated for the `aggregator-platform` experiment;
- `kubectl`;
- Helm 3; and
- `curl`.

You also need an SSH key registered with Slices. Register it if necessary:

```bash
slices pubkey register ~/.ssh/id_ed25519.pub
```

All remaining commands should be run from the repository root unless stated
otherwise.

## 1. Verify access to the launcher

Confirm that the Slices CLI can open an SSH connection to `kublauncher`:

```bash
slices bi ssh kublauncher \
  --experiment aggregator-platform \
  --proxy auto
```

Exit the remote shell after the connection succeeds. Resolve Slices login,
experiment access, or SSH-key errors before proceeding.

The `--proxy auto` option uses a Slices jump proxy when the experiment provides
one and otherwise connects directly. If automatic detection does not work, use
`--proxy on` where the commands below use `--proxy auto`.

## 2. Install or refresh the kubeconfig

Skip this section if the following command already finds a working context
supplied with the PACSOI configuration files:

```bash
kubectl config get-contexts admin@aggregator-cluster
```

Otherwise, display the underlying SSH command for the launcher:

```bash
slices bi ssh kublauncher \
  --experiment aggregator-platform \
  --proxy auto \
  --show command
```

Use the displayed connection details to copy `~/.kube/config` from the
launcher to the local machine as `~/.kube/slices-config`. Check that the
cluster's server address in that file is:

```text
https://193.191.169.51:6443
```

Merge the Slices configuration with the existing local kubeconfig instead of
replacing it:

```bash
KUBECONFIG=~/.kube/config:~/.kube/slices-config \
  kubectl config view --flatten > ~/.kube/merged
mv ~/.kube/merged ~/.kube/config
```

Confirm that the expected context is installed:

```bash
kubectl config get-contexts admin@aggregator-cluster
```

Kubeconfig files can contain credentials. Keep `~/.kube/slices-config` and
`~/.kube/config` private and do not commit them to Git.

## 3. Allow your public IP through the proxy

Run the proxy configuration script:

```bash
./slices/configure-proxy.sh
```
or:
```bash
make slices-configure-proxy
```

The script:

- detects your public IPv4 address using `ifconfig.me`;
- generates the Nginx stream configuration;
- retains the UGent, Slices, and private-network allow rules;
- backs up the configuration currently installed on the launcher;
- validates the replacement with `nginx -t` and restores the backup if
  validation fails; and
- reloads Nginx after successful validation.

If automatic public-IP detection is wrong, provide the address explicitly:

```bash
PUBLIC_IP=203.0.113.10 ./slices/configure-proxy.sh
```

The IP must be the public IPv4 address seen by the launcher. A local WSL
`172.x.x.x` address is not valid. Your public address can change after changing
networks, enabling or disabling a VPN, or receiving a new address from an ISP;
rerun the script when this happens.

The script already contains the PACSOI control-plane and worker defaults. Only
override them when the cluster addresses have changed:

```bash
PUBLIC_IP=203.0.113.10 \
SLICES_CONTROL_PLANE=10.10.210.167 \
SLICES_WORKER=10.10.211.115 \
SLICES_SSH_PROXY=on \
./slices/configure-proxy.sh
```

`SLICES_WORKER` is an Nginx entry point for the Traefik NodePort. It does not
need to list every Kubernetes worker because Kubernetes forwards NodePort
traffic to the appropriate Traefik pod.

## 4. Verify cluster access

Query the cluster through the named context:

```bash
kubectl --context admin@aggregator-cluster get nodes
```

All expected nodes should eventually report `Ready`. For node addresses and
additional details, use:

```bash
kubectl --context admin@aggregator-cluster get nodes -o wide
```

The setup is complete once these commands succeed.

## 5. Deploy the Aggregator Platform

Ensure the PACSOI Helm values file is available at `config/slices.yaml`, then
deploy or update the platform:

```bash
make slices-deploy
```

This command applies the custom resource definitions, installs or upgrades the
Helm release, and waits for the Aggregator Server deployment to become ready.

## Routine access

For later sessions, first try the verification command:

```bash
kubectl --context admin@aggregator-cluster get nodes
```

You do not need to repeat the complete setup when it succeeds. If the proxy
rejects or times out after your public IP changed, rerun:

```bash
./slices/configure-proxy.sh
```
