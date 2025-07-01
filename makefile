# Declare phony targets so make always runs these commands
.PHONY: minikube-init minikube-start minikube-clean containers-build containers-load run

# 'init-minikube' target: start minikube, build images, then load them into minikube
minikube-init: minikube-start containers-build containers-load

# Start minikube with Docker driver
minikube-start:
	@echo "🚀 Starting Minikube with Docker driver..."
	@minikube start --driver=docker

# Stop and delete the minikube cluster (clean up)
minikube-clean:
	@echo "🧹 Stopping and deleting Minikube cluster..."
	@minikube stop
	@minikube delete

# Build Docker images for all containers in the folder
containers-build:
	@echo "🔨 Building Docker images for all containers..."
	@for dir in containers/*; do \
		if [ -d "$$dir" ]; then \
			echo "📦 Building image for container: $$(basename $$dir)"; \
			docker build $$dir -t $$(basename $$dir); \
		fi; \
	done

# Load all built images into minikube's Docker environment
containers-load:
	@echo "📤 Loading Docker images into Minikube..."
	@for dir in containers/*; do \
		if [ -d "$$dir" ]; then \
			echo "📥 Loading image: $$(basename $$dir) into Minikube"; \
			minikube image load $$(basename $$dir); \
		fi; \
	done

# Run the Go application
run:
	@echo "🏃 Running the Go application..."
	@go run .
