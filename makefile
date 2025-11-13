# Use KinD (Kubernetes in Docker)
KIND_CLUSTER_NAME ?= aggregator

# Declare phony targets so make always runs these commands
.PHONY: kubernettes-init kubernettes-start kubernettes-clean kubernettes-dashboard-start kubernettes-dashboard-proxy containers-all containers-build containers-load run kubernettes-generate-key-pair

# 'init-kubernettes' target: start KinD, build images, then load them into KinD
kubernettes-init: kubernettes-start containers-build containers-load kubernettes-generate-key-pair

# deploy Kubernetes dashboard (for KinD)
kubernettes-dashboard-start:
	@echo "📥 Installing Kubernetes Dashboard to KinD cluster '$(KIND_CLUSTER_NAME)'..."
	helm repo add kubernetes-dashboard https://kubernetes.github.io/dashboard
	helm repo update
	helm upgrade --install kubernetes-dashboard kubernetes-dashboard/kubernetes-dashboard --create-namespace -n kubernetes-dashboard
	@echo "⏳ Waiting for Kubernetes Dashboard pods to become ready..."
	@kubectl wait --namespace kubernetes-dashboard \
	  --for=condition=ready pod \
	  --selector=app.kubernetes.io/instance=kubernetes-dashboard \
	  --timeout=120s
	@sleep 1
	@echo "🔐 Retrieving token for \`admin-user\`..."
	@token=$$(kubectl -n kubernetes-dashboard create token admin-user 2>/dev/null || true); \
	if [ -z "$$token" ]; then \
	  echo "⚠️  No token found for \`admin-user\`. The ServiceAccount may not exist."; \
	  echo "   Create one and bind it to cluster-admin (for local/test clusters) with a manifest like \`dashboard-admin.yaml\` and run: kubectl apply -f dashboard-admin.yaml"; \
	else \
	  echo "✅ Dashboard ready — open: https://localhost:8443 with token:"; \
	  echo "$$token"; \
	fi
	@kubectl -n kubernetes-dashboard port-forward svc/kubernetes-dashboard-kong-proxy 8443:443

# Set up key pair for uma-proxy
kubernettes-generate-key-pair:
	@echo "🔑 Generating key pair for uma-proxy..."
	@openssl genrsa -out uma-proxy.key 4096
	@openssl req -x509 -new -nodes -key uma-proxy.key -sha256 -days 3650 -out uma-proxy.crt -subj "/CN=Aggregator MITM CA"
	@echo "🗑️ Deleting existing Kubernetes secret for uma-proxy key pair if it exists..."
	@kubectl delete secret uma-proxy-key-pair -n default --ignore-not-found
	@echo "🔐 Creating Kubernetes secret for uma-proxy key pair..."
	@kubectl create secret generic uma-proxy-key-pair --from-file=uma-proxy.crt=uma-proxy.crt --from-file=uma-proxy.key=uma-proxy.key -n default
	@echo "🗑️ Cleaning up generated key pair files..."
	@rm uma-proxy.crt uma-proxy.key

# Start KinD cluster
kubernettes-start:
	@echo "🚀 Ensuring KinD cluster '$(KIND_CLUSTER_NAME)' is running..."
	@kind get clusters | grep -qx '$(KIND_CLUSTER_NAME)' || kind create cluster --name '$(KIND_CLUSTER_NAME)'
	@echo "⏳ Waiting for cluster to be ready..."
	@kubectl wait --for=condition=ready node --all --timeout=120s

# Stop and delete the KinD cluster (clean up)
kubernettes-clean:
	@echo "🧹 Deleting KinD cluster '$(KIND_CLUSTER_NAME)'..."
	@kind delete cluster --name '$(KIND_CLUSTER_NAME)'

# Build and load Docker images for all containers or a specific container
containers-all: containers-build containers-load

# Build Docker images for a specific container or all containers
containers-build:
	@if [ -n "$(name)" ]; then \
		echo "📦 Building image for container: $(name)"; \
		docker build containers/$(name) -t $(name); \
	else \
		echo "🔨 Building Docker images for all containers..."; \
		for dir in containers/*; do \
			if [ -d "$$dir" ]; then \
				echo "📦 Building image for container: $$(basename $$dir)"; \
				docker build $$dir -t $$(basename $$dir); \
			fi; \
		done; \
	fi

# Load Docker images for a specific container or all containers into KinD
containers-load:
	@if [ -n "$(name)" ]; then \
		echo "📥 Loading image: $(name) into KinD cluster '$(KIND_CLUSTER_NAME)'"; \
		kind load docker-image $(name) --name '$(KIND_CLUSTER_NAME)'; \
	else \
		echo "📤 Loading Docker images into KinD cluster '$(KIND_CLUSTER_NAME)'..."; \
		for dir in containers/*; do \
			if [ -d "$$dir" ]; then \
				img=$$(basename $$dir); \
				echo "📥 Loading image: $$img into KinD"; \
				kind load docker-image $$img --name '$(KIND_CLUSTER_NAME)'; \
			fi; \
		done; \
	fi

# Run the Go application
run:
	@echo "🏃 Running the Go application..."
	@go run .

