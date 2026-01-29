.PHONY: kind-init kind-start kind-stop kind-delete \
        containers-build containers-load containers-all \
        kind-generate-egress-key-pair kind-generate-ingress-key kind-generate-aggregator-key-pair kind-generate-keys \
        kind-start-traefik \
        kind-deploy deploy kind-undeploy undeploy \
			  configure-etc-hosts clean-etc-hosts configure-coredns \
				kind-dashboard \
        docker-clean deploy integration-test unit-test

# ------------------------
# Aggregator deployment
# ------------------------

deploy:
	@echo "📄 Deploying aggregator application..."
	@helm upgrade --install aggregator-platform ./aggregator-platform -f $(CONFIG) \
		-n aggregator-platform --create-namespace \
		--set-file tls.selfSigned.crt=aggregator.crt \
  	--set-file tls.selfSigned.key=aggregator.key
	@kubectl rollout status deployment aggregator-server -n aggregator-platform --timeout=120s
	@echo "✅ Aggregator application successfully deployed!"

kind-deploy: 
	$(MAKE) deploy CONFIG=kind/helm-config.yaml

undeploy:
	@echo "🧹 Stopping aggregator deployment..."
	@if kind get clusters 2>/dev/null | grep -q "aggregator"; then \
		kubectl config use-context kind-aggregator || true; \
		helm uninstall aggregator-platform -n aggregator-platform || true; \
		kubectl delete namespace aggregator-platform --ignore-not-found || true; \
	else \
		echo "ℹ️ Kind cluster 'aggregator' does not exist, skipping cleanup"; \
	fi
	@echo "✅ Aggregator deployment stopped!"

kind-undeploy: undeploy

# ------------------------
# Local cluster setup
# ------------------------

kind-init: kind-start containers-all kind-generate-keys kind-start-traefik
	@echo "✅ Local Kind cluster and environment initialized!"

kind-delete:
	@echo "🧹 Deleting Kind cluster..."
	@kind delete cluster --name aggregator
	@echo "🧹 Deleting keys..."
	@rm -f aggregator.crt aggregator.key private_key.pem

	@echo "🔧 Removing self-signed CA from trusted store..."
	@if [ "$$(uname)" = "Linux" ]; then \
		sudo rm -f /usr/local/share/ca-certificates/aggregator.crt; \
		sudo update-ca-certificates --fresh; \
	elif [ "$$(uname)" = "Darwin" ]; then \
		sudo security delete-certificate -c "aggregator.local" /Library/Keychains/System.keychain || true; \
	else \
		echo "⚠️ Unsupported OS: Please manually remove aggregator.crt from your trusted store"; \
	fi

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
	@echo "🔑 Generating tls key pair for aggregator..."
	@openssl req -x509 -nodes -days 365 \
  -newkey rsa:2048 \
  -keyout aggregator.key \
  -out aggregator.crt \
  -subj "/CN=aggregator.local" \
  -addext "subjectAltName=DNS:aggregator.local"
	@echo "✅ TLS key pair generated"
	@echo "🔧 Adding self-signed CA to local trusted store..."
	@if [ "$$(uname)" = "Linux" ]; then \
		sudo cp aggregator.crt /usr/local/share/ca-certificates/aggregator.crt; \
		sudo update-ca-certificates; \
	elif [ "$$(uname)" = "Darwin" ]; then \
		sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain aggregator.crt; \
	else \
		echo "⚠️ Unsupported OS: Please manually add aggregator.crt to your trusted store"; \
	fi
	@echo "✅ Self-signed CA installed."

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

kind-generate-ingress-key:
	@echo "🔑 Generating RSA private key for ingress-uma..."
	@if [ ! -f private_key.pem ]; then \
		openssl genrsa -out private_key.pem 2048; \
		echo "✅ Generated private_key.pem"; \
	else \
		echo "ℹ️ private_key.pem already exists, skipping"; \
	fi

kind-generate-keys: kind-generate-aggregator-key-pair kind-generate-egress-key-pair kind-generate-ingress-key

# ------------------------
# Ingress Controller
# ------------------------

kind-start-traefik:
	@echo "📄 Deploying Traefik Ingress Controller..."
	@kubectl config use-context kind-aggregator
	@helm repo add traefik https://traefik.github.io/charts || true
	@helm repo update
	@helm upgrade --install aggregator-traefik traefik/traefik \
		--namespace aggregator-traefik --create-namespace \
		--set ingressClass.enabled=true \
		--set ingressClass.name=aggregator-traefik \
		--set ports.web.hostPort=80 \
		--set ports.websecure.hostPort=443 \
		--set service.type=ClusterIP \
		--set providers.kubernetesCRD.allowCrossNamespace=true
	@kubectl rollout status deployment aggregator-traefik -n aggregator-traefik --timeout=180s
	@echo "✅ Traefik deployment is ready!"

# ------------------------
# Container targets
# ------------------------

containers-build:
	@echo "🔨 Building Docker images..."
	@if [ -n "$(CONTAINER)" ]; then \
		dir="containers/$(CONTAINER)"; \
		if [ -d "$$dir" ]; then \
			docker build "$$dir" -t "$(CONTAINER):latest"; \
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
	@kubectl apply -f kind/cluster/coredns/local-hosts.yaml
	@kubectl rollout restart deployment coredns -n kube-system
	@kubectl wait --for=condition=ready pod -l kind-app=kube-dns -n kube-system --timeout=60s
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
	@cd integration-test && go mod download && go test -v -timeout 20m ./...

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
	@helm repo add kubernetes-dashboard https://kubernetes.github.io/dashboard/ || true
	@helm repo update
	@helm upgrade --install kubernetes-dashboard kubernetes-dashboard/kubernetes-dashboard \
		--namespace kubernetes-dashboard --create-namespace
	@kubectl apply -f kind/dashboard/admin.yaml
	@kubectl wait --namespace kubernetes-dashboard \
		--for=condition=ready pod \
		--selector=app.kubernetes.io/instance=kubernetes-dashboard \
		--timeout=120s
	@echo "🔑 Dashboard token:"
	@kubectl get secret admin-user -n kubernetes-dashboard -o jsonpath="{.data.token}" | base64 -d && echo ""
	@kubectl -n kubernetes-dashboard port-forward svc/kubernetes-dashboard-kong-proxy 8443:443
