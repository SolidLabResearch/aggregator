# Local Setup Guide

This guide walks you through setting up a local **kind** (Kubernetes in Docker) cluster and deploying the **Aggregator Server**.

## Prerequisites

Make sure the following tools are installed:

- `make`
- `kind`
- `kubectl`
- `helm`
- `mkcert`

### Install Dependencies

#### Install make
```bash
sudo apt update
sudo apt install -y make
```

#### Install kind
```bash
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind
```

#### Install kubectl
```bash
curl -LO "https://dl.k8s.io/release/\$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/
```

#### Install helm
```bash
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```

#### Install mkcert
```bash
sudo apt update
sudo apt install -y mkcert libnss3-tools
```

---

## 1. TLS Configuration

To enable HTTPS, generate a local certificate for the Aggregator Server.

```bash
mkcert -install
mkcert aggregator.local
```

Update your Helm values file:

```yaml
tls:
  enabled: true
  secretName: tls-secret
  mode: selfsigned
  selfSigned:
    crt: aggregator.crt
    key: aggregator.key
```

### Trust the Local Certificate Authority

Node.js does not automatically trust mkcert certificates. Set:

```bash
export NODE_EXTRA_CA_CERTS="\$(mkcert -CAROOT)/rootCA.pem"
```

---

## 2. Create the kind Cluster

Use the provided configuration file:

```
kind/cluster-config.yaml
```

Run:

```bash
make kind-init
```

This will:
- Create the kind cluster
- Load local containers from `/containers`
- Install the Traefik ingress controller

## 3. Configure Cluster DNS

The Aggregator Server rewrites `localhost` to `host.docker.internal` for Docker-based services.

If you run services outside Docker (e.g., WSL), update [`kind/localhosts.yaml`](/kind/localhosts.yaml) with an IP - hostname mapping:

```yaml
hosts {
  <WSL IP> wsl.local
  fallthrough
}
```

Apply changes:

```bash
make configure-coredns
```

### Update Local Hosts File

Ensure your machine resolves the same hostnames:

```bash
make configure-etc-hosts HOSTS="aggregator.local wsl.local"
```

If you use automated deploy/undeploy commands, update the `HOSTS` variable in the Makefile.

## 4. Configure the Aggregator Server

The server is configured using [`kind/helm-config.yaml`](/kind/helm-config.yaml).

### External Access

Define how the server is accessed externally:

```bash
external:
  host: aggregator.local
  httpPort: 5080
  httpsPort: 5443
```

> Use the ports exposed by your kind cluster or reverse proxy.

---

### Authentication

Set up authentication using one of the supported servers:

- [Community Solid Server (CSS)](/docs/css-setup.md)
- [Kvasir Solid Server (KSS)](/docs/kss-setup.md)

Follow the relevant setup documentation before continuing.

---

### Add Transformations (Services)

To add Aggregator Services:

1. [Create your service](/docs/creating-services.md).
2. Place it inside the `/containers` directory.
3. Load it into the cluster:

```
make containers-all CONTAINER=<service-folder>
```

This step is automatically executed during `make kind-init`.

## 5. Deploy the Aggregator Server

Once everything is configured:

```bash
make kind-deploy
```

This deploys the platform using [`kind/heml-config.yaml`](/kind/helm-config.yaml).

## 6. Next Steps

Your Aggregator Server should now be running locally.

You can continue with:

- [Deploying aggregators](/docs/deploying-aggregators.md)
- [Deploying services](/docs/deploying-services.md)
- [Running a full example setup](/docs/pacsoi-example.md)

---