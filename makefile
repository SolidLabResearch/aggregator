.PHONY: kind-init kind-start kind-stop kind-delete \
        containers-build containers-load containers-all \
        kind-generate-egress-key-pair kind-generate-ingress-key kind-generate-aggregator-key-pair kind-generate-keys \
        kind-start-traefik kind-stop-traefik \
        kind-deploy kind-tls-deploy deploy \
        kind-undeploy undeploy \
        configure-etc-hosts clean-etc-hosts configure-coredns \
        kind-dashboard \
        docker-clean integration-test unit-test

# ------------------------
# Variables
# ------------------------

NAMESPACE        := aggregator-platform
KIND_CLUSTER     := aggregator
KIND_CONTEXT     := kind-$(KIND_CLUSTER)
KIND_HOSTS       := aggregator.local wsl.local

TLS_SECRET_NAME  := aggregator-tls-secret
TLS_MANUAL       ?= true

# ------------------------
# Aggregator deployment
# ------------------------

deploy:
	@echo "📄 Deploying aggregator application..."
	@helm upgrade --install aggregator-platform ./aggregator-platform \
		-f $(CONFIG) \
		-n $(NAMESPACE) --create-namespace \
		$(HELM_EXTRA_ARGS)
	@kubectl rollout status deployment aggregator-server -n $(NAMESPACE) --timeout=120s
	@echo "✅ Aggregator application successfully deployed!"

kind-deploy:
	$(MAKE) configure-etc-hosts HOSTS="$(KIND_HOSTS)"
	@if [ "$(TLS_MANUAL)" = "true" ]; then \
		$(MAKE) kind-tls-dev; \
		$(MAKE) deploy CONFIG=kind/helm-config.yaml \
			HELM_EXTRA_ARGS="--set tls.enabled=true \
				--set tls.mode=manual \
				--set tls.secretName=$(TLS_SECRET_NAME) \
				--set-file tls.certificate.crt=aggregator.local.pem \
				--set-file tls.certificate.key=aggregator.local-key.pem"; \
		$(MAKE) kind-tls-clean; \
	else \
		$(MAKE) deploy CONFIG=kind/helm-config.yaml \
			HELM_EXTRA_ARGS="--set tls.enabled=false"; \
	fi

undeploy:
	@echo "🧹 Stopping aggregator deployment..."
	@if kind get clusters 2>/dev/null | grep -q "$(KIND_CLUSTER)"; then \
		kubectl config use-context $(KIND_CONTEXT) || true; \
		helm uninstall aggregator-platform -n $(NAMESPACE) || true; \
		kubectl delete namespace $(NAMESPACE) --ignore-not-found || true; \
	else \
		echo "ℹ️ Kind cluster '$(KIND_CLUSTER)' does not exist, skipping cleanup"; \
	fi
	@echo "✅ Aggregator deployment stopped!"

kind-undeploy:
	$(MAKE) clean-etc-hosts HOSTS="$(KIND_HOSTS)"
	$(MAKE) undeploy

# ------------------------
# Local cluster setup
# ------------------------

kind-init: kind-start containers-all kind-start-traefik
	@echo "✅ Local Kind cluster and environment initialized!"

kind-delete:
	@echo "🧹 Deleting Kind cluster..."
	@kind delete cluster --name $(KIND_CLUSTER)
	@echo "🧹 Deleting keys..."
	@rm -f aggregator.crt aggregator.key private_key.pem
	@echo "✅ Cleanup complete"

kind-start:
	@echo "🚀 Starting Kind cluster..."
	@if kind get clusters 2>/dev/null | grep -q "$(KIND_CLUSTER)"; then \
		for node in $$(docker ps -a -q --filter "name=$(KIND_CLUSTER)" --filter "status=exited"); do \
			echo "▶️ Starting node $$node..."; \
			docker start $$node >/dev/null; \
		done; \
		kubectl config use-context $(KIND_CONTEXT); \
	else \
		kind create cluster --name $(KIND_CLUSTER) --config kind/cluster-config.yaml; \
		kubectl wait --for=condition=Ready nodes --all --timeout=120s; \
		kubectl config use-context $(KIND_CONTEXT); \
	fi
	@echo "✅ Kind cluster ready!"

kind-stop:
	@echo "🛑 Stopping Kind cluster '$(KIND_CLUSTER)'..."
	@if kind get clusters 2>/dev/null | grep -q "$(KIND_CLUSTER)"; then \
		for node in $$(docker ps -q --filter "name=$(KIND_CLUSTER)"); do \
			echo "⏸️  Stopping node $$node..."; \
			docker stop $$node >/dev/null; \
		done; \
		echo "✅ Kind cluster stopped!"; \
	else \
		echo "ℹ️ Kind cluster '$(KIND_CLUSTER)' not found, nothing to stop"; \
	fi

# ------------------------
# TLS
# ------------------------

kind-tls-dev:
	@echo "🔐 Generating TLS certificates..."
	@mkcert aggregator.local
	@echo "✅ TLS certificates generated!"

kind-tls-clean:
	@echo "🧹 Removing TLS certificate files..."
	@rm -f aggregator.local.pem aggregator.local-key.pem
	@echo "✅ TLS certificate files removed!"

# ------------------------
# Ingress Controller
# ------------------------

kind-start-traefik:
	@echo "📄 Deploying Traefik Ingress Controller..."
	@kubectl config use-context $(KIND_CONTEXT)
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
	@kubectl config use-context $(KIND_CONTEXT)
	@helm uninstall aggregator-traefik -n aggregator-traefik || true
	@kubectl delete namespace aggregator-traefik --ignore-not-found
	@echo "✅ Traefik has been removed!"

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
	@kubectl config use-context $(KIND_CONTEXT)
	@if [ -n "$(CONTAINER)" ]; then \
		kind load docker-image "$(CONTAINER):latest" --name $(KIND_CLUSTER); \
	else \
		for dir in containers/*; do \
			name=$$(basename $$dir); \
			kind load docker-image "$$name:latest" --name $(KIND_CLUSTER); \
		done \
	fi

containers-all: containers-build containers-load

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
	@kubectl config use-context $(KIND_CONTEXT)
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
	@kubectl config use-context $(KIND_CONTEXT)
	@helm repo add kubernetes-dashboard https://kubernetes-retired.github.io/dashboard/ || true
	@helm repo update
	@helm upgrade --install kubernetes-dashboard kubernetes-dashboard/kubernetes-dashboard \
		--namespace kubernetes-dashboard --create-namespace
	@kubectl apply -f kind/dashboard-admin.yaml
	@kubectl wait --namespace kubernetes-dashboard \
		--for=condition=ready pod \
		--selector=app.kubernetes.io/instance=kubernetes-dashboard \
		--timeout=120s
	@echo "🔑 Dashboard token:"
	@kubectl get secret admin-user -n kubernetes-dashboard -o go-template="{{.data.token | base64decode}}"
	@kubectl -n kubernetes-dashboard port-forward svc/kubernetes-dashboard-kong-proxy 8443:443 --address=0.0.0.0