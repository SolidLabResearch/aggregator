.PHONY: kind-init kind-start kind-stop kind-dashboard \
	containers-build containers-load containers-all \
	kind-generate-key-pair \
	enable-localhost disable-localhost \
	kind-deploy \
	kind-clean

# ------------------------
# Kind targets
# ------------------------

# Initialize kind cluster, build/load containers, generate keys, deploy YAML manifests
kind-init: kind-start containers-all kind-generate-key-pair kind-dashboard

# Start kind cluster
kind-start:
	@echo "🚀 Creating kind cluster..."
	@if ! kind get clusters | grep -q "aggregator"; then \
		kind create cluster --name aggregator --config k8s/kind-config.yaml; \
	else \
		echo "Kind cluster 'aggregator' already exists."; \
	fi
	@echo "🚀 Configuring kubernetes dashboard"
	@helm repo add kubernetes-dashboard https://kubernetes.github.io/dashboard/
	@helm upgrade --install kubernetes-dashboard kubernetes-dashboard/kubernetes-dashboard --create-namespace --namespace kubernetes-dashboard
	@kubectl apply -f k8s/dashboard-admin.yaml

# Stop and delete kind cluster
kind-stop:
	@echo "🧹 Deleting kind cluster..."
	@kind delete cluster --name aggregator

# Optional: dashboard (kubectl proxy)
# Get token: kubectl get secret admin-user -n kubernetes-dashboard -o jsonpath="{.data.token}" | base64 -d
kind-dashboard:
	@echo "🚀 Starting kubectl proxy for Kubernetes dashboard..."
	@kubectl wait --namespace kubernetes-dashboard \
  	--for=condition=ready pod \
  	--selector=app.kubernetes.io/instance=kubernetes-dashboard \
  	--timeout=120s
	@kubectl -n kubernetes-dashboard port-forward svc/kubernetes-dashboard-kong-proxy 8443:443
	

# ------------------------
# Container targets
# ------------------------

# Build Docker images
containers-build:
	@echo "🔨 Building Docker images for containers..."
	@if [ -n "$(CONTAINER)" ]; then \
		dir="containers/$(CONTAINER)"; \
		if [ -d "$$dir" ]; then \
			echo "📦 Building $(CONTAINER)..."; \
			docker build "$$dir" -t "$(CONTAINER):latest"; \
		else \
			echo "❌ Container $(CONTAINER) does not exist!"; \
			exit 1; \
		fi \
	else \
		for dir in containers/*; do \
			if [ -d "$$dir" ]; then \
				name=$$(basename $$dir); \
				echo "📦 Building $$name..."; \
				docker build "$$dir" -t "$$name:latest"; \
			fi \
		done \
	fi

# Load Docker images into kind
containers-load:
	@echo "📤 Loading container images into kind..."
	@if [ -n "$(CONTAINER)" ]; then \
		name="$(CONTAINER)"; \
		echo "📥 Loading $$name into kind..."; \
		kind load docker-image "$$name:latest" --name aggregator; \
	else \
		for dir in containers/*; do \
			if [ -d "$$dir" ]; then \
				name=$$(basename $$dir); \
				echo "📥 Loading $$name into kind..."; \
				kind load docker-image "$$name:latest" --name aggregator; \
			fi \
		done \
	fi

# Build and load all containers
containers-all: containers-build containers-load

# ------------------------
# Deploy YAML manifests with temporary key pair for uma-proxy
# ------------------------
kind-start-nginx:
	@echo "📄 Deploying NGINX Ingress Controller..."
	@kubectl apply -f https://kind.sigs.k8s.io/examples/ingress/deploy-ingress-nginx.yaml

	@echo "📄 Waiting for ingress controller to be ready..."
	@kubectl wait --namespace ingress-nginx \
	  --for=condition=ready pod \
	  --selector=app.kubernetes.io/component=controller \
	  --timeout=90s

kind-deploy:
	@echo "📄 Applying aggregator namespace..."
	@kubectl apply -f k8s/aggregator/aggregator-ns.yaml

	@echo "📄 Creating secret for ingress-uma..."
	@kubectl -n aggregator-ns create secret generic ingress-uma-key \
		--from-file=private_key.pem=k8s/aggregator/private_key.pem \
		--dry-run=client -o yaml | kubectl apply -f -

	@echo "📄 Applying aggregator ConfigMap..."
	@kubectl apply -f k8s/aggregator/aggregator-config.yaml

	@echo "📄 Applying aggregator deployment and service..."
	@kubectl apply -f k8s/aggregator/aggregator.yaml

	@echo "📄 Applying ingress-uma..."
	@kubectl apply -f k8s/aggregator/ingress-uma.yaml

	@echo "📄 Adding localhost entries for ingress hosts..."
	@grep -qxF "127.0.0.1 aggregator.local" /etc/hosts || sudo -- sh -c "echo '127.0.0.1 aggregator.local' >> /etc/hosts"

	@echo "✅ Resources deployed to kind"

# ------------------------
# Cleanup kind deployment
# ------------------------

kind-stop-nginx:
	@echo "🧹 Deleting NGINX Ingress Controller..."
	@kubectl delete ns ingress-nginx --ignore-not-found
	@kubectl delete clusterrole ingress-nginx --ignore-not-found
	@kubectl delete clusterrolebinding ingress-nginx --ignore-not-found

kind-clean:
	@echo "🧹 Deleting aggregator cluster-wide roles..."
	@kubectl delete clusterrole aggregator-namespace-manager --ignore-not-found
	@kubectl delete clusterrolebinding aggregator-namespace-manager-binding --ignore-not-found

	@echo "🧹 Deleting aggregator namespace..."
	@kubectl delete namespace aggregator-ns --ignore-not-found

	@echo "🧹 Removing localhost entries..."
	@sudo sed -i.bak '/aggregator\.local/d' /etc/hosts

	@echo "✅ Cleanup complete"
