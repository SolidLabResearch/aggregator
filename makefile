.PHONY: init kind-start kind-stop kind-dashboard \
	containers-build containers-load containers-all \
	kind-generate-key-pair generate-ingress-key \
	kind-deploy kind-start-traefik kind-start-cleaner \
	kind-clean clean kind-stop-traefik \
	kind-undeploy stop \
	enable-wsl \
	docker-clean deploy \
	integration-test unit-test

# ------------------------
# Kind targets
# ------------------------

# Initialize kind cluster, build/load containers, generate keys, start cleaner
init: kind-start containers-all kind-generate-key-pair generate-ingress-key kind-start-cleaner

# Start kind cluster
kind-start:
	@echo "🚀 Creating kind cluster..."
	@if kind get clusters 2>/dev/null | grep -q "aggregator"; then \
		echo "Kind cluster 'aggregator' already exists."; \
		if ! kubectl config get-contexts kind-aggregator >/dev/null 2>&1; then \
			echo "⚠️  Context 'kind-aggregator' not found, deleting and recreating cluster..."; \
			kind delete cluster --name aggregator; \
			kind create cluster --name aggregator --config k8s/cluster/kind-config.yaml; \
			echo "⏳ Waiting for cluster to be ready..."; \
			kubectl wait --for=condition=Ready nodes --all --timeout=120s; \
		fi; \
	else \
		kind create cluster --name aggregator --config k8s/cluster/kind-config.yaml; \
		echo "⏳ Waiting for cluster to be ready..."; \
		kubectl wait --for=condition=Ready nodes --all --timeout=120s; \
	fi
	@kubectl config use-context kind-aggregator
	@echo "✅ Kind cluster is ready!"

# Stop and delete kind cluster
kind-stop:
	@echo "🧹 Deleting kind cluster..."
	@kind delete cluster --name aggregator

# Optional: dashboard (kubectl proxy)
# Get token: kubectl get secret admin-user -n kubernetes-dashboard -o jsonpath="{.data.token}" | base64 -d
kind-dashboard:
	@echo "🚀 Configuring kubernetes dashboard"
	@kubectl config use-context kind-aggregator
	@if ! helm repo list | grep -q "kubernetes-dashboard"; then \
		helm repo add kubernetes-dashboard https://kubernetes.github.io/dashboard/; \
	fi
	@helm repo update
	@helm upgrade --install kubernetes-dashboard kubernetes-dashboard/kubernetes-dashboard --create-namespace --namespace kubernetes-dashboard
	@kubectl apply -f k8s/cluster/dashboard/admin.yaml
	@echo "🚀 Starting kubectl proxy for Kubernetes dashboard..."
	@kubectl wait --namespace kubernetes-dashboard \
  	--for=condition=ready pod \
  	--selector=app.kubernetes.io/instance=kubernetes-dashboard \
  	--timeout=120s
	@echo "🔑 The token is:"
	@kubectl get secret admin-user -n kubernetes-dashboard -o jsonpath="{.data.token}" | base64 -d && echo ""
	@kubectl -n kubernetes-dashboard port-forward svc/kubernetes-dashboard-kong-proxy 8443:443

# Set up key pair for uma-proxy
kind-generate-key-pair:
	@echo "🔑 Generating key pair for uma-proxy..."
	@kubectl config use-context kind-aggregator
	@openssl genrsa -out uma-proxy.key 4096
	@openssl req -x509 -new -nodes -key uma-proxy.key -sha256 -days 3650 -out uma-proxy.crt -subj "/CN=Aggregator MITM CA"
	@echo "🗑️ Deleting existing Kubernetes secret for uma-proxy key pair if it exists..."
	@kubectl delete secret uma-proxy-key-pair -n default --ignore-not-found
	@echo "🔐 Creating Kubernetes secret for uma-proxy key pair..."
	@kubectl create secret generic uma-proxy-key-pair --from-file=uma-proxy.crt=uma-proxy.crt --from-file=uma-proxy.key=uma-proxy.key -n default
	@echo "🗑️ Cleaning up generated key pair files..."
	@rm uma-proxy.crt uma-proxy.key

# Generate RSA private key for ingress-uma
generate-ingress-key:
	@echo "🔑 Generating RSA private key for ingress-uma..."
	@if [ ! -f private_key.pem ]; then \
		openssl genrsa -out private_key.pem 2048; \
		echo "✅ Generated private_key.pem"; \
	else \
		echo "ℹ️  private_key.pem already exists, skipping generation"; \
	fi

# ------------------------
# Container targets
# ------------------------

# add CONTAINER=<container name> to handle a specific container

# Build Docker images
containers-build:
	@echo "🔨 Building Docker images for containers..."
	@if [ -n "$(CONTAINER)" ]; then \
		dir="containers/$(CONTAINER)"; \
		if [ -d "$$dir" ]; then \
			echo "🗑️  Removing old $(CONTAINER) images..."; \
			docker images "$(CONTAINER)" --format "{{.ID}}" | xargs -r docker rmi -f 2>/dev/null || true; \
			echo "📦 Building $(CONTAINER)..."; \
			docker build "$$dir" -t "$(CONTAINER):latest"; \
		else \
			echo "❌ Container $(CONTAINER) does not exist!"; \
			exit 1; \
		fi \
	else \
		echo "🗑️  Removing old container images..."; \
		find containers -maxdepth 1 -mindepth 1 -type d -exec basename {} \; | \
		xargs -I {} sh -c 'docker images "{}" --format "{{.ID}}" | xargs -r docker rmi -f 2>/dev/null || true'; \
		find containers -maxdepth 1 -mindepth 1 -type d | \
		xargs -I {} -P $$(nproc) sh -c '\
			name=$$(basename {}); \
			echo "📦 Building $$name..."; \
			if docker build {} -t "$$name:latest"; then \
				echo "✅ Built $$name"; \
			else \
				echo "❌ Failed to build $$name"; \
				exit 1; \
			fi \
		' && echo "✅ All containers built successfully" || (echo "❌ Build failed"; exit 1); \
	fi

# Load Docker images into kind
containers-load:
	@echo "📤 Loading container images into kind..."
	@kubectl config use-context kind-aggregator 2>/dev/null || (echo "❌ Kind cluster not ready"; exit 1)
	@if [ -n "$(CONTAINER)" ]; then \
		name="$(CONTAINER)"; \
		echo "📥 Loading $$name into kind..."; \
		kind load docker-image "$$name:latest" --name aggregator; \
	else \
		find containers -maxdepth 1 -mindepth 1 -type d | \
		xargs -I {} -P 4 sh -c '\
			name=$$(basename {}); \
			echo "📥 Loading $$name into kind..."; \
			if kind load docker-image "$$name:latest" --name aggregator; then \
				echo "✅ Loaded $$name"; \
			else \
				echo "❌ Failed to load $$name"; \
				exit 1; \
			fi \
		' && echo "✅ All containers loaded successfully" || (echo "❌ Loading failed"; exit 1); \
	fi

# Build and load all containers
containers-all: containers-build containers-load

# Clean up Docker dangling and unused images
docker-clean:
	@echo "🧹 Cleaning up Docker images..."
	@echo "🗑️  Removing dangling images..."
	@docker image prune -f
	@echo "🗑️  Removing unused images..."
	@docker image prune -a -f --filter "until=24h"
	@echo "✅ Docker cleanup complete"

# ------------------------
# Deploy YAML manifests with temporary key pair for uma-proxy
# ------------------------
kind-start-traefik:
	@echo "📄 Deploying Traefik Ingress Controller..."
	@kubectl config use-context kind-aggregator
	@helm repo add traefik https://traefik.github.io/charts
	@helm repo update
	@helm upgrade --install aggregator-traefik traefik/traefik \
		--namespace aggregator-traefik \
		--create-namespace \
		--set ingressClass.enabled=true \
		--set ingressClass.name=aggregator-traefik \
		--set ports.web.hostPort=80 \
		--set ports.websecure.hostPort=443 \
		--set service.type=ClusterIP \
		--set providers.kubernetesCRD.allowCrossNamespace=true
	@echo "⏳ Waiting for Traefik deployment to be ready..."
	@kubectl rollout status deployment aggregator-traefik -n aggregator-traefik --timeout=180s
	@echo "✅ Traefik deployment is ready!"

kind-start-cleaner:
	@echo "📄 Deploying aggregator-cleaner controller..."
	@kubectl config use-context kind-aggregator
	@kubectl apply -f k8s/namespaces/ops.yaml
	@kubectl apply -k k8s/ops/
	@echo "⏳ Waiting for aggregator-cleaner to be ready..."
	@kubectl wait --namespace aggregator-ops \
	  --for=condition=available deployment/aggregator-cleaner \
	  --timeout=60s || true

	@echo "✅ Aggregator cleaner deployed"

kind-deploy:
	@echo "📄 Deploying aggregator application..."
	@kubectl config use-context kind-aggregator

	@echo "📄 Applying custom resources definitions..."
	@kubectl apply -f k8s/cluster/crds/transformation.yaml

	@echo "📄 Applying namespaces..."
	@kubectl apply -f k8s/namespaces/app.yaml

	@echo "📄 Applying Traefik middlewares..."
	@kubectl apply -f k8s/app/traefik/middlewares.yaml

	@echo "📄 Creating secret for ingress-uma..."
	@kubectl -n aggregator-app create secret generic ingress-uma-key \
		--from-file=private_key.pem=private_key.pem \
		--dry-run=client -o yaml | kubectl apply -f -

	@echo "📄 Applying aggregator ConfigMap and transformations..."
	@kubectl apply -f k8s/config/app-config.yaml
	@kubectl apply -f k8s/config/transformations.yaml

	@echo "📄 Adding localhost entries for ingress hosts..."
	@grep -qxF "127.0.0.1 aggregator.local" /etc/hosts || sudo -- sh -c "echo '127.0.0.1 aggregator.local' >> /etc/hosts"
	@grep -qxF "127.0.0.1 wsl.local" /etc/hosts || sudo -- sh -c "echo '127.0.0.1 wsl.local' >> /etc/hosts"

	@echo "📄 Applying ingress-uma..."
	@kubectl apply -f k8s/app/ingress-uma.yaml
	@echo "⏳ Waiting for ingress-uma deployment to be ready..."
	@kubectl rollout status deployment ingress-uma -n aggregator-app --timeout=90s
	@echo "⏳ Waiting for ingress-uma via Ingress to be reachable..."
	@for i in {1..30}; do \
			STATUS=$$(curl -s -o /dev/null -w "%{http_code}" http://aggregator.local/uma/.well-known/jwks.json || echo "000"); \
			if [ "$$STATUS" = "200" ]; then \
					echo "✅ Ingress-uma endpoint is ready"; \
					break; \
			else \
					echo "Waiting for Ingress JWKS endpoint... (status=$$STATUS)"; \
					sleep 2; \
			fi; \
	done
	@echo "📄 Applying aggregator deployment and service..."
	@kubectl apply -f k8s/app/aggregator.yaml
	@echo "⏳ Waiting for aggregator deployment to be ready..."
	@kubectl rollout status deployment aggregator-server -n aggregator-app --timeout=120s

	@echo "✅ Resources deployed to kind"

deploy: kind-start-traefik kind-deploy
	@echo "✅ Aggregator deployment complete"

# ------------------------
# Cleanup kind deployment
# ------------------------

kind-undeploy:
	@echo "🧹 Stopping aggregator deployment (keeping Traefik and cleaner running)..."
	@if kind get clusters 2>/dev/null | grep -q "aggregator"; then \
		echo "🔧 Setting kubectl context..."; \
		kubectl config use-context kind-aggregator || true; \
		echo "🧹 Deleting aggregator namespace..."; \
		kubectl delete namespace aggregator-app --ignore-not-found || true; \
	else \
		echo "ℹ️  Kind cluster 'aggregator' does not exist, skipping deployment cleanup"; \
	fi
	@echo "🧹 Removing localhost entries..."
	@sudo sed -i.bak '/aggregator\.local/d' /etc/hosts || true
	@sudo sed -i.bak '/wsl\.local/d' /etc/hosts || true
	@echo "✅ Deployment stopped (Traefik and cleaner still running)"

kind-stop-traefik:
	@if kind get clusters 2>/dev/null | grep -q "aggregator"; then \
		echo "🧹 Deleting Traefik Ingress Controller..."; \
		kubectl config use-context kind-aggregator || true; \
		kubectl delete namespace aggregator-traefik --ignore-not-found || true; \
		echo "✅ Traefik Ingress Controller removed successfully."; \
	else \
		echo "ℹ️  Kind cluster 'aggregator' does not exist, skipping Traefik cleanup"; \
	fi

kind-clean:
	@echo "🧹 Cleaning up aggregator deployment..."
	@if kind get clusters 2>/dev/null | grep -q "aggregator"; then \
		echo "🔧 Setting kubectl context..."; \
		kubectl config use-context kind-aggregator || true; \
		echo "🧹 Deleting aggregator cluster-wide roles..."; \
		kubectl delete clusterrole aggregator-namespace-manager --ignore-not-found || true; \
		kubectl delete clusterrolebinding aggregator-namespace-manager-binding --ignore-not-found || true; \
		kubectl delete clusterrole aggregator-cleaner-role --ignore-not-found || true; \
		kubectl delete clusterrolebinding aggregator-cleaner-binding --ignore-not-found || true; \
		echo "🧹 Deleting aggregator namespace..."; \
		kubectl delete namespace aggregator-app --ignore-not-found || true; \
		$(MAKE) kind-stop-cleaner; \
		$(MAKE) kind-stop-traefik; \
	else \
		echo "ℹ️  Kind cluster 'aggregator' does not exist, skipping Kubernetes cleanup"; \
	fi
	@echo "🧹 Removing localhost entries..."
	@sudo sed -i.bak '/aggregator\.local/d' /etc/hosts || true
	@sudo sed -i.bak '/wsl\.local/d' /etc/hosts || true
	@echo "🗑️ Removing generated key files..."
	@rm -f private_key.pem
	@echo "✅ Cleanup complete"

# Clean everything and delete the entire kind cluster
clean: kind-clean kind-stop docker-clean
	@echo "✅ Complete cleanup finished - cluster deleted"

# Stop deployment and Traefik
stop: kind-undeploy kind-stop-traefik
	@echo "✅ All services stopped (cluster and cleaner still running)"

# -------------------------
# localhost dns configuration
# -------------------------

configure-coredns-local:
	@echo "📄 Configuring CoreDNS for .local domains..."
	@kubectl config use-context kind-aggregator
	@kubectl apply -f k8s/cluster/coredns/local-hosts.yaml
	@kubectl rollout restart deployment coredns -n kube-system
	@echo "⏳ Waiting for CoreDNS to be ready..."
	@kubectl wait --for=condition=ready pod -l k8s-app=kube-dns -n kube-system --timeout=60s
	@echo "✅ CoreDNS configured for .local domains"

# ------------------------
# Tests
# ------------------------
integration-test:
	@echo "🧪 Running integration tests..."
	@cd integration-test && go mod download && go test -v -timeout 20m ./...

unit-test:
	@echo "🧪 Running container unit tests (Go only)..."
	@for dir in containers/*; do \
		if [ -f "$$dir/go.mod" ]; then \
			echo "➡️  $$dir"; \
			( cd "$$dir" && go test ./... ); \
		fi; \
	done

