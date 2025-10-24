.PHONY: minikube-init minikube-start minikube-stop minikube-dashboard-start \
	containers-build containers-load containers-all \
	minikube-generate-key-pair \
	enable-localhost disable-localhost \
	minikube-deploy \
	minikube-clean \
	expose-aggregator close-aggregator

# ------------------------
# Minikube targets
# ------------------------

# Initialize Minikube, build/load containers, generate keys, deploy YAML manifests, start dashboard
minikube-init: minikube-start containers-all minikube-generate-key-pair minikube-dashboard-start

# Start Minikube with Docker driver
minikube-start:
	@echo "🚀 Starting Minikube with Docker driver..."
	@minikube start --driver=docker

# Stop and delete the Minikube cluster (clean up)
minikube-stop:
	@echo "🧹 Stopping and deleting Minikube..."
	@minikube stop
	@minikube delete

# Deploy Minikube dashboard
minikube-dashboard-start:
	@echo "🚀 Starting kubectl proxy for Minikube dashboard..."
	@minikube dashboard

# ------------------------
# Container targets
# ------------------------

# Build Docker images
containers-build:
	@echo "🔨 Building Docker images for containers..."
	@for dir in containers/*; do \
		if [ -d "$$dir" ]; then \
			name=$$(basename $$dir); \
			echo "📦 Building $$name..."; \
			docker build "$$dir" -t "$$name:latest"; \
		fi \
	done

# Load Docker images into Minikube
containers-load:
	@echo "📤 Loading container images into Minikube..."
	@for dir in containers/*; do \
		if [ -d "$$dir" ]; then \
			name=$$(basename $$dir); \
			echo "📥 Loading $$name into Minikube..."; \
			minikube image load "$$name:latest"; \
		fi \
	done

# Build and load all containers
containers-all: containers-build containers-load

# ------------------------
# Deploy YAML manifests with temporary key pair for uma-proxy
# ------------------------

minikube-deploy:
	@echo "🔑 Generating temporary key pair for uma-proxy..."
	@openssl genrsa -out uma-proxy.key 4096
	@openssl req -x509 -new -nodes -key uma-proxy.key -sha256 -days 3650 -out uma-proxy.crt -subj "/CN=Aggregator MITM CA"
	@echo "📄 Applying namespaces..."
	@kubectl apply -f k8s/uma-proxy-ns.yaml
	@kubectl apply -f k8s/aggregator-ns.yaml
	@echo "🔐 Creating Kubernetes secret for uma-proxy..."
	@kubectl create secret generic uma-proxy-key-pair \
		--from-file=uma-proxy.crt=uma-proxy.crt \
		--from-file=uma-proxy.key=uma-proxy.key \
		-n uma-proxy-ns --dry-run=client -o yaml | kubectl apply -f -
	@echo "📄 Applying resources..."
	@export MINIKUBE_IP=$$(minikube ip); \
	envsubst < k8s/aggregator-config.yaml | kubectl apply -f -; \
	kubectl apply -f k8s/uma-proxy.yaml; \
	kubectl apply -f k8s/aggregator.yaml
	@echo "🗑️ Cleaning up generated key pair files..."
	@rm uma-proxy.crt uma-proxy.key
	@echo "✅ Resources deployed to Minikube"

# ------------------------
# Cleanup Minikube deployment
# ------------------------

minikube-clean:
	@echo "🧹 Deleting aggregator actor pods and services in aggregator-ns..."
	@kubectl delete pods,services -n aggregator-ns --all --ignore-not-found
	@echo "🧹 Deleting aggregator deployment, service account, role, rolebinding..."
	@kubectl delete deployment,serviceaccount,role,rolebinding -n aggregator-ns --all --ignore-not-found
	@echo "🧹 Deleting aggregator namespace..."
	@kubectl delete namespace aggregator-ns --ignore-not-found
	@echo "🧹 Deleting uma-proxy pod and service in uma-proxy-ns..."
	@kubectl delete pods,services -n uma-proxy-ns --all --ignore-not-found
	@echo "🧹 Deleting uma-proxy service account..."
	@kubectl delete serviceaccount -n uma-proxy-ns uma-proxy-sa --ignore-not-found
	@echo "🧹 Deleting uma-proxy namespace..."
	@kubectl delete namespace uma-proxy-ns --ignore-not-found
	@echo "✅ Cleanup complete."

# ------------------------
# Aggregator port-forward for WSL
# ------------------------

# Start port-forward
expose-aggregator:
	@echo "🚀 Port-forwarding aggregator to localhost:5000..."
	@kubectl port-forward -n aggregator-ns deployment/aggregator 5000:5000
