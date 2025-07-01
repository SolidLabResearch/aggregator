# Aggregator

An aggregator using uma: https://github.com/SolidLabResearch/user-managed-access as the authorization server.

## Requirements
This project requires a kubernetes cluster and a running uma server.

### Kubernetes Cluster
install a kubernetes cluster with minikube:
```bash
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube
```

when minikube is installed, initialize it:
```bash
make init-minikube
```
This will start the minikube cluster, build all the containers, and load them into the minikube cluster.
To only build or load the containers without starting the cluster, you can run:
```bash
make build-containers
make load-containers
```
And to start or stop the minikube cluster, you can run:
```bash
make start-minikube
make clean-minikube
```

### uma Server
To install the uma server, you first need to clone the uma repository:
```bash
git clone https://github.com/SolidLabResearch/user-managed-access
cd user-managed-access/packages/uma
```
Make sure you have node.js and npm installed with a version of at least 20.0.0, and run `corepack enable`.
Then install the dependencies:
```bash
yarn install
```
Finally, the uma server can be started with:
```bash
yarn start
```

### Run the Aggregator
To run the aggregator, you can use the following command:
```bash
make run
```

