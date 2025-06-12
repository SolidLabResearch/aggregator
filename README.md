# Aggregator

An aggregator using uma: https://github.com/SolidLabResearch/user-managed-access as the authorization server.

This project requires a kubernetes cluster and a running uma server.
install a kubernetes cluster with minikube:
```bash
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube
```
and start it:
```bash
minikube start --driver=docker
```



