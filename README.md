# Aggregator

An aggregator using uma: https://github.com/SolidLabResearch/user-managed-access as the authorization server.

## Requirements
This project requires a kubernetes cluster and a running uma server.

### Kubernetes Cluster
Install KinD (Kubernetes in Docker):
```bash
# For AMD64 / x86_64
[ $(uname -m) = x86_64 ] && curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.30.0/kind-linux-amd64
# For ARM64
[ $(uname -m) = aarch64 ] && curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.30.0/kind-linux-arm64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind
```

Initialize a local KinD cluster and prepare images/secrets:
```bash
make kubernettes-init
```
This will ensure the KinD cluster exists, build all the containers, and load them into the KinD cluster, then create the UMA proxy key-pair secret and deploy the Kubernetes Dashboard.

To build or load containers without touching the cluster, run:
```bash
make containers-build   # Build the containers
make containers-load    # Load the containers into the KinD cluster
make containers-all     # Build and load the containers
```
You can target a specific container with the `name` variable. For example, to build and load only the uma-proxy container:
```bash
make containers-all name=uma-proxy
```
To start or delete the KinD cluster explicitly:
```bash
make kubernettes-start
make kubernettes-clean
```
Optionally, choose a different cluster name:
```bash
make kubernettes-start KIND_CLUSTER=my-cluster
```

### UMA Server
To install the UMA server, first clone the repository:
```bash
git clone https://github.com/SolidLabResearch/user-managed-access
cd user-managed-access/packages/uma
```
Make sure you have Node.js and npm installed (>= 20.0.0), and run `corepack enable`.
Then install dependencies:
```bash
yarn install
```
Start the UMA server:
```bash
yarn start
```

### Run the Aggregator
To run the aggregator locally:
```bash
make run
```

### Demo
An easy way to test the aggregator is by running `node client-test/create-actor.js` to create an actor.
Ensure the UMA server is running and has policies configured so you can access the appropriate endpoints.
Then run `node client-test/get-actor.js` to retrieve details on the created actor and its results.
