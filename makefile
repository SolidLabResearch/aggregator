# Declare phony targets so make always runs these commands
.PHONY: minikube-init minikube-start minikube-clean containers-all containers-build containers-load run

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

# Load Docker images for a specific container or all containers into Minikube
containers-load:
	@if [ -n "$(name)" ]; then \
		echo "📥 Loading image: $(name) into Minikube"; \
		minikube image load $(name); \
	else \
		echo "📤 Loading Docker images into Minikube..."; \
		for dir in containers/*; do \
			if [ -d "$$dir" ]; then \
				echo "📥 Loading image: $$(basename $$dir) into Minikube"; \
				minikube image load $$(basename $$dir); \
			fi; \
		done; \
	fi

# Run the Go application
run:
	@echo "🏃 Running the Go application..."
	@go run .
