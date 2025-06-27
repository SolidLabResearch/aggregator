# Declare phony targets so make always runs these commands
.PHONY: init start build load run clean

# 'init' target: start minikube, build image, then load it into minikube
init: start build load

# Start minikube with Docker driver
start:
	minikube start --driver=docker

# Build the Docker image from the specified directory and tag it 'uma-proxy'
build:
	docker build containers/uma-proxy -t uma-proxy

# Load the locally built image into minikube's Docker environment
load:
	minikube image load uma-proxy

# Run the Go application
run:
	go run .

# Stop and delete the minikube cluster (clean up)
clean:
	minikube stop
	minikube delete