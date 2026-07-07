.PHONY: kind-init kind-start kind-stop kind-delete \
        containers-build containers-load containers-all \
        kind-generate-egress-key-pair kind-generate-ingress-key kind-generate-aggregator-key-pair kind-generate-keys \
        kind-start-traefik \
        kind-deploy deploy kind-undeploy undeploy \
			  configure-etc-hosts clean-etc-hosts configure-coredns \
				kind-dashboard \
        docker-clean deploy integration-test unit-test

# ------------------------
# Makefile configuration
# ------------------------

CONFIG_DIR  ?= ./config
CONFIG_FILE ?= local.yaml
SERVICE_DIR := $(CONFIG_DIR)/services
FNO_DIR     := $(CONFIG_DIR)/fno
SERVICE_FILES := $(wildcard $(SERVICE_DIR)/*.yaml)
FNO_FILES     := $(wildcard $(FNO_DIR)/*.yaml)
VALUES_FLAGS  := -f $(CONFIG_DIR)/$(CONFIG) \
                 $(foreach f,$(SERVICE_FILES),-f $(f)) \
                 $(foreach f,$(FNO_FILES),-f $(f))

GITHUB_ORG=knows-aggregator
GITHUB_PROJECT=k8s-aggregator

# ------------------------
# Aggregator deployment
# ------------------------

deploy:
	@echo "📄 Deploying aggregator application..."
	@helm upgrade --install aggregator-platform ./aggregator-platform \
		$(VALUES_FLAGS) \
		-n aggregator-platform --create-namespace
	@kubectl rollout status deployment aggregator-server -n aggregator-platform --timeout=120s
	@echo "✅ Aggregator application successfully deployed!"

kind-deploy:
	$(MAKE) configure-etc-hosts HOSTS="aggregator.local wsl.local"
	$(MAKE) deploy CONFIG=$(CONFIG_FILE)

undeploy:
	@echo "🧹 Stopping aggregator deployment..."
	@if kind get clusters 2>/dev/null | grep -q "aggregator"; then \
		kubectl config use-context kind-aggregator || true; \
		helm uninstall aggregator-platform -n aggregator-platform || true; \
		kubectl delete namespace aggregator-platform --ignore-not-found || true; \
		kubectl delete crd serviceconfigurations.aggregator.example.org --ignore-not-found || true; \
		kubectl delete crd fnodescriptions.aggregator.example.org --ignore-not-found || true; \
	else \
		echo "ℹ️ Kind cluster 'aggregator' does not exist, skipping cleanup"; \
	fi
	@echo "✅ Aggregator deployment stopped!"

kind-undeploy: 
	$(MAKE) clean-etc-hosts HOSTS="aggregator.local wsl.local" undeploy

# ------------------------
# Local cluster setup
# ------------------------

kind-init: kind-start containers-all kind-start-traefik
	@echo "✅ Local Kind cluster and environment initialized!"

kind-delete:
	@echo "🧹 Deleting Kind cluster..."
	@kind delete cluster --name aggregator
	@echo "🧹 Deleting keys..."
	@rm -f aggregator.crt aggregator.key private_key.pem
	@echo "✅ Cleanup complete"

kind-start:
	@echo "🚀 Starting Kind cluster..."
	@if kind get clusters 2>/dev/null | grep -q "aggregator"; then \
		# Start any stopped nodes \
		for node in $$(docker ps -a -q --filter "name=aggregator" --filter "status=exited"); do \
			echo "▶️ Starting node $$node..."; \
			docker start $$node >/dev/null; \
		done; \
		kubectl config use-context kind-aggregator; \
	else \
		# Cluster does not exist, create new \
		kind create cluster --name aggregator --config kind/cluster-config.yaml; \
		kubectl wait --for=condition=Ready nodes --all --timeout=120s; \
		kubectl config use-context kind-aggregator; \
	fi
	@echo "✅ Kind cluster ready!"

kind-stop:
	@echo "🛑 Stopping Kind cluster 'aggregator'..."
	@if kind get clusters 2>/dev/null | grep -q "aggregator"; then \
		for node in $$(docker ps -q --filter "name=aggregator"); do \
			echo "⏸️  Stopping node $$node..."; \
			docker stop $$node >/dev/null; \
		done; \
		echo "✅ Kind cluster stopped!"; \
	else \
		echo "ℹ️ Kind cluster 'aggregator' not found, nothing to stop"; \
	fi

# ------------------------
# Key generation
# ------------------------

kind-generate-aggregator-key-pair:
	@mkcert aggregator.local 

kind-generate-egress-key-pair:
	@echo "🔑 Generating key pair for uma-proxy..."
	@kubectl config use-context kind-aggregator
	@openssl genrsa -out uma-proxy.key 4096
	@openssl req -x509 -new -nodes -key uma-proxy.key -sha256 -days 3650 \
		-out uma-proxy.crt -subj "/CN=Aggregator MITM CA"
	@kubectl delete secret uma-proxy-key-pair -n default --ignore-not-found
	@kubectl create secret generic uma-proxy-key-pair \
		--from-file=uma-proxy.crt=uma-proxy.crt \
		--from-file=uma-proxy.key=uma-proxy.key -n default
	@rm uma-proxy.crt uma-proxy.key

kind-generate-keys: kind-generate-aggregator-key-pair kind-generate-egress-key-pair

# ------------------------
# Ingress Controller
# ------------------------

kind-start-traefik:
	@echo "📄 Deploying Traefik Ingress Controller..."
	@kubectl config use-context kind-aggregator
	@helm repo add aggregator-traefik https://traefik.github.io/charts || true
	@helm repo update
	@helm upgrade --install aggregator-traefik aggregator-traefik/traefik \
		--namespace aggregator-traefik --create-namespace \
		--set ingressClass.enabled=true \
		--set ingressClass.name=aggregator-traefik \
		--set ports.web.hostPort=80 \
		--set ports.websecure.hostPort=443 \
		--set service.type=ClusterIP
	@kubectl rollout status deployment aggregator-traefik -n aggregator-traefik --timeout=180s
	@echo "✅ Traefik deployment is ready!"

kind-stop-traefik:
	@echo "🛑 Removing Traefik Ingress Controller..."
	@kubectl config use-context kind-aggregator
	@helm uninstall aggregator-traefik -n aggregator-traefik || true
	@kubectl delete namespace aggregator-traefik --ignore-not-found
	@echo "✅ Traefik has been removed!"

slices-start-traefik:
	@echo "📄 Deploying Traefik Ingress Controller on Slices..."
	@kubectl config use-context admin@aggregator-cluster
	@helm repo add traefik https://traefik.github.io/charts || true
	@helm repo update
	@helm upgrade --install traefik traefik/traefik \
		--namespace traefik --create-namespace \
		--set ingressClass.enabled=true \
		--set ingressClass.name=traefik \
		--set ports.web.nodePort=30080 \
		--set ports.websecure.nodePort=30443 \
		--set service.type=NodePort
	@kubectl rollout status deployment traefik -n traefik --timeout=180s
	@echo "✅ Traefik deployment is ready!"


# ------------------------
# Container targets
# ------------------------

containers-build:
	@echo "🔨 Building Docker images..."
	@if [ -n "$(CONTAINER)" ]; then \
		dir="containers/$(CONTAINER)"; \
		if [ -d "$$dir" ]; then \
			docker build --no-cache "$$dir" -t "$(CONTAINER):latest"; \
		else \
			echo "❌ Container $(CONTAINER) does not exist!"; exit 1; \
		fi \
	else \
		for dir in containers/*; do \
			name=$$(basename $$dir); \
			docker build $$dir -t "$$name:latest"; \
		done \
	fi

containers-load:
	@echo "📤 Loading Docker images into Kind..."
	@kubectl config use-context kind-aggregator
	@if [ -n "$(CONTAINER)" ]; then \
		kind load docker-image "$(CONTAINER):latest" --name aggregator; \
	else \
		for dir in containers/*; do \
			name=$$(basename $$dir); \
			kind load docker-image "$$name:latest" --name aggregator; \
		done \
	fi

containers-all: containers-build containers-load

containers-push: containers-build
	@echo "📤 Pushing Docker images to ghcr.io..."
	@if [ -n "$(CONTAINER)" ]; then \
		docker tag "$(CONTAINER):latest" "ghcr.io/$(GITHUB_ORG)/$(GITHUB_PROJECT)/$(CONTAINER):latest"; \
		docker push "ghcr.io/$(GITHUB_ORG)/$(GITHUB_PROJECT)/$(CONTAINER):latest"; \
	else \
		for dir in containers/*; do \
			name=$$(basename $$dir); \
			docker tag "$$name:latest" "ghcr.io/$(GITHUB_ORG)/$(GITHUB_PROJECT)/$$name:latest"; \
			docker push "ghcr.io/$(GITHUB_ORG)/$(GITHUB_PROJECT)/$$name:latest"; \
		done \
	fi

# ------------------------
# Local host / DNS configuration
# ------------------------

configure-etc-hosts:
	@echo "📄 Adding localhost entries..."
	@for host in $(HOSTS); do \
		grep -qxF "127.0.0.1 $$host" /etc/hosts || \
		sudo -- sh -c "echo '127.0.0.1 $$host' >> /etc/hosts"; \
	done
	@echo "✅ Hosts added: $(HOSTS)"

clean-etc-hosts:
	@echo "🧹 Cleaning localhost entries..."
	@for host in $(HOSTS); do \
		sudo sed -i.bak "/$$host/d" /etc/hosts || true; \
	done
	@echo "✅ Hosts removed: $(HOSTS)"

configure-coredns:
	@echo "📄 Configuring CoreDNS for .local domains..."
	@kubectl config use-context kind-aggregator
	@kubectl apply -f kind/localhosts.yaml
	@kubectl rollout restart deployment coredns -n kube-system
	@kubectl wait --for=condition=ready pod -l k8s-app=kube-dns -n kube-system --timeout=60s
	@echo "✅ CoreDNS configured for .local domains"

# ------------------------
# Docker cleanup
# ------------------------

docker-clean:
	@echo "🧹 Cleaning up Docker images..."
	@docker image prune -af --filter "label!=kindest/node"

# ------------------------
# Tests
# ------------------------

integration-test:
	@echo "🧪 Running integration tests..."
	@cd integration-test && go mod download && go test -count=1 -v -timeout 20m ./...

unit-test:
	@echo "🧪 Running unit tests..."
	@for dir in containers/*; do \
		if [ -f "$$dir/go.mod" ]; then \
			( cd $$dir && go test ./... ); \
		fi \
	done

# ------------------------
# Dashboard
# ------------------------

kind-dashboard:
	@echo "🚀 Deploying Kubernetes Dashboard..."
	@kubectl config use-context kind-aggregator
	# Add and update Helm repo
	@helm repo add kubernetes-dashboard https://kubernetes-retired.github.io/dashboard/ || true
	@helm repo update
	# Install or upgrade the dashboard
	@helm upgrade --install kubernetes-dashboard kubernetes-dashboard/kubernetes-dashboard \
		--namespace kubernetes-dashboard --create-namespace
	# Apply admin ServiceAccount and ClusterRoleBinding
	@kubectl apply -f kind/dashboard-admin.yaml
	# Wait for the dashboard pod to be ready
	@kubectl wait --namespace kubernetes-dashboard \
		--for=condition=ready pod \
		--selector=app.kubernetes.io/instance=kubernetes-dashboard \
		--timeout=120s
	# Show the dashboard token
	@echo "🔑 Dashboard token:"
	@kubectl get secret admin-user -n kubernetes-dashboard -o go-template="{{.data.token | base64decode}}"
	@kubectl -n kubernetes-dashboard port-forward svc/kubernetes-dashboard-kong-proxy 8443:443 --address=0.0.0.0

slices-dashboard:
	@echo "🚀 Deploying Kubernetes Dashboard on Slices cluster..."
	@kubectl config use-context admin@aggregator-cluster
	@helm repo add kubernetes-dashboard https://kubernetes-retired.github.io/dashboard/ || true
	@helm repo update
	@helm upgrade --install kubernetes-dashboard kubernetes-dashboard/kubernetes-dashboard \
		--namespace kubernetes-dashboard --create-namespace \
		--set app.ingress.enabled=false
	@kubectl apply -f slices/dashboard/admin.yaml
	@kubectl apply -f slices/dashboard/ingress.yaml
	@kubectl wait --namespace kubernetes-dashboard \
		--for=condition=ready pod \
		--selector=app.kubernetes.io/instance=kubernetes-dashboard \
		--timeout=180s
	@echo "🔑 Dashboard token:"
	@kubectl get secret admin-user -n kubernetes-dashboard \
		-o go-template="{{.data.token | base64decode}}"
	@echo ""
	@echo "🌐 Access at: https://dashboard.aggregator.pacsoi.knows.idlab.ugent.be"