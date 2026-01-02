.PHONY: kind-init kind-start kind-stop kind-dashboard \
	containers-build containers-load containers-all \
	kind-generate-key-pair \
	enable-localhost disable-localhost \
	kind-deploy \
	kind-clean \
	enable-wsl

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

# Stop and delete kind cluster
kind-stop:
	@echo "🧹 Deleting kind cluster..."
	@kind delete cluster --name aggregator

# Optional: dashboard (kubectl proxy)
# Get token: kubectl get secret admin-user -n kubernetes-dashboard -o jsonpath="{.data.token}" | base64 -d
kind-dashboard:
	@echo "🚀 Configuring kubernetes dashboard"
	@if ! helm repo list | grep -q "kubernetes-dashboard"; then \
		helm repo add kubernetes-dashboard https://kubernetes.github.io/dashboard/; \
	fi
	@helm repo update
	@helm upgrade --install kubernetes-dashboard kubernetes-dashboard/kubernetes-dashboard --create-namespace --namespace kubernetes-dashboard
	@kubectl apply -f k8s/dashboard-admin.yaml
	@echo "🚀 Starting kubectl proxy for Kubernetes dashboard..."
	@kubectl wait --namespace kubernetes-dashboard \
  	--for=condition=ready pod \
  	--selector=app.kubernetes.io/instance=kubernetes-dashboard \
  	--timeout=120s
	@echo "🔑 The token is:"
	@kubectl get secret admin-user -n kubernetes-dashboard -o jsonpath="{.data.token}" | base64 -d && echo ""
	@kubectl -n kubernetes-dashboard port-forward svc/kubernetes-dashboard-kong-proxy 8443:443
	

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
			echo "📦 Building $(CONTAINER)..."; \
			docker build "$$dir" -t "$(CONTAINER):latest"; \
		else \
			echo "❌ Container $(CONTAINER) does not exist!"; \
			exit 1; \
		fi \
	else \
		find containers -maxdepth 1 -mindepth 1 -type d | \
		xargs -I {} -P $$(nproc) sh -c '\
			name=$$(basename {}); \
			echo "📦 Building $$name..."; \
			docker build {} -t "$$name:latest" && echo "✅ Built $$name" || echo "❌ Failed to build $$name"; \
		'; \
	fi

# Load Docker images into kind
containers-load:
	@echo "📤 Loading container images into kind..."
	@if [ -n "$(CONTAINER)" ]; then \
		name="$(CONTAINER)"; \
		echo "📥 Loading $$name into kind..."; \
		kind load docker-image "$$name:latest" --name aggregator; \
	else \
		find containers -maxdepth 1 -mindepth 1 -type d | \
		xargs -I {} -P 4 sh -c '\
			name=$$(basename {}); \
			echo "📥 Loading $$name into kind..."; \
			kind load docker-image "$$name:latest" --name aggregator && echo "✅ Loaded $$name" || echo "❌ Failed to load $$name"; \
		'; \
	fi

# Build and load all containers
containers-all: containers-build containers-load

# ------------------------
# Deploy YAML manifests with temporary key pair for uma-proxy
# ------------------------
kind-start-traefik:
	@echo "📄 Deploying Traefik Ingress Controller..."
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
	@kubectl apply -f k8s/ops/ns.yaml
	@kubectl apply -f k8s/ops/cleaner.yaml

	@echo "📄 Waiting for aggregator-cleaner to be ready..."
	@kubectl wait --namespace aggregator-ops \
	  --for=condition=available deployment/aggregator-cleaner \
	  --timeout=60s || true

	@echo "✅ Aggregator cleaner deployed"

kind-deploy:
	@echo "📄 Applying aggregator namespace..."
	@kubectl apply -f k8s/app/ns.yaml

	@echo "📄 Applying traefik config..."
	@kubectl apply -f k8s/app/traefik-config.yaml

	@echo "📄 Creating secret for ingress-uma..."
	@kubectl -n aggregator-app create secret generic ingress-uma-key \
		--from-file=private_key.pem=private_key.pem \
		--dry-run=client -o yaml | kubectl apply -f -

	@echo "📄 Applying aggregator ConfigMap..."
	@kubectl apply -f k8s/app/config.yaml

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

# ------------------------
# Cleanup kind deployment
# ------------------------

kind-stop-cleaner:
	@echo "🧹 Removing aggregator-cleaner controller..."
	@kubectl delete -f k8s/ops/cleaner.yaml --ignore-not-found
	@echo "✅ Aggregator cleaner removed"

kind-stop-traefik:
	@echo "🧹 Deleting Traefik Ingress Controller..."
	# Delete the namespace (optional, removes all resources inside)
	@kubectl delete namespace aggregator-traefik --ignore-not-found
	@echo "✅ Traefik Ingress Controller removed successfully."

kind-clean:
	@echo "🧹 Deleting aggregator cluster-wide roles..."
	@kubectl delete clusterrole aggregator-namespace-manager --ignore-not-found
	@kubectl delete clusterrolebinding aggregator-namespace-manager-binding --ignore-not-found

	@echo "🧹 Deleting aggregator namespace..."
	@kubectl delete namespace aggregator-app --ignore-not-found

	@echo "🧹 Removing localhost entries..."
	@sudo sed -i.bak '/aggregator\.local/d' /etc/hosts
	@sudo sed -i.bak '/wsl\.local/d' /etc/hosts

	@echo "✅ Cleanup complete"

# -------------------------
# wsl support
# -------------------------

enable-wsl:
	@echo "🔍 Detecting WSL2 IP..."
	$(eval WSL_IP := $(shell hostname -I | awk '{print $$1}'))
	@echo "Detected WSL2 IP: $(WSL_IP)"

	@echo "🧠 Backing up CoreDNS ConfigMap..."
	@kubectl -n kube-system get configmap coredns -o yaml > /tmp/coredns.yaml

	@echo "🧩 Patching CoreDNS..."
	@awk -v ip="$(WSL_IP)" '\
		/^data:/ {print; inData=1; next} \
		inData && /^\s*Corefile:/ { \
			print; \
			print "    wsl.local:53 {"; \
			print "        hosts {"; \
			print "            " ip " wsl.local"; \
			print "            fallthrough"; \
			print "        }"; \
			print "    }"; \
			next \
		} \
		{print} \
	' /tmp/coredns.yaml > /tmp/coredns-patched.yaml

	@echo "📦 Applying patched ConfigMap..."
	@kubectl -n kube-system apply -f /tmp/coredns-patched.yaml >/dev/null

	@echo "♻️ Restarting CoreDNS deployment..."
	@kubectl -n kube-system rollout restart deployment coredns >/dev/null

	@echo "✅ Done! 'wsl.local' now resolves to $(WSL_IP)"

