package utils

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type TestEnvironment struct {
	KubeClient        *kubernetes.Clientset
	AggregatorURL     string
	UMAServerURL      string
	OIDCIssuer        string
	ResourceServerUrl string
	ClusterName       string
	cleanupFuncs      []func() error
	umaServerProcess  *exec.Cmd
	portForwardCmd    *exec.Cmd
}

type ActorConfig struct {
	ID          string
	Name        string
	Description string
}

type UserConfig struct {
	Username string
	Email    string
	Password string
}

type Actor struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

func SetupTestEnvironment(ctx context.Context) (*TestEnvironment, error) {
	env := &TestEnvironment{
		ClusterName:   "aggregator-test",
		AggregatorURL: "http://localhost:8080",
	}

	if err := env.setupKubernetesCluster(ctx); err != nil {
		return nil, fmt.Errorf("failed to setup kubernetes cluster: %w", err)
	}

	if err := env.setupKubeClient(); err != nil {
		return nil, fmt.Errorf("failed to setup kubernetes client: %w", err)
	}

	if err := env.buildAndLoadContainers(ctx); err != nil {
		return nil, fmt.Errorf("failed to build and load containers: %w", err)
	}

	if err := env.deployAggregator(ctx); err != nil {
		return nil, fmt.Errorf("failed to deploy aggregator: %w", err)
	}

	return env, nil
}

func (env *TestEnvironment) setupKubernetesCluster(ctx context.Context) error {
	fmt.Println("Creating Kind cluster...")

	cmd := exec.CommandContext(ctx, "kind", "get", "clusters")
	output, err := cmd.CombinedOutput()
	if err == nil && strings.Contains(string(output), env.ClusterName) {
		fmt.Println("Cluster already exists, deleting...")
		deleteCmd := exec.CommandContext(ctx, "kind", "delete", "cluster", "--name", env.ClusterName)
		if err := deleteCmd.Run(); err != nil {
			return fmt.Errorf("failed to delete existing cluster: %w", err)
		}
	}

	createCmd := exec.CommandContext(ctx, "kind", "create", "cluster",
		"--name", env.ClusterName,
		"--config", "kind-test-config.yaml")
	createCmd.Stdout = os.Stdout
	createCmd.Stderr = os.Stderr

	if err := createCmd.Run(); err != nil {
		return fmt.Errorf("failed to create kind cluster: %w", err)
	}

	env.cleanupFuncs = append(env.cleanupFuncs, func() error {
		cmd := exec.Command("kind", "delete", "cluster", "--name", env.ClusterName)
		return cmd.Run()
	})

	return nil
}

func (env *TestEnvironment) setupKubeClient() error {
	kubeconfig := clientcmd.NewDefaultClientConfigLoadingRules().GetDefaultFilename()
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to build kubeconfig: %w", err)
	}

	env.KubeClient, err = kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	return nil
}

func (env *TestEnvironment) buildAndLoadContainers(ctx context.Context) error {
	fmt.Println("Building containers...")

	buildCmd := exec.CommandContext(ctx, "make", "-C", "..", "containers-build")
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr

	if err := buildCmd.Run(); err != nil {
		return fmt.Errorf("failed to build containers: %w", err)
	}

	fmt.Println("Loading containers into Kind...")

	containers := []string{"aggregator-server", "aggregator", "egress-uma", "ingress-uma", "file-server"}
	for _, container := range containers {
		loadCmd := exec.CommandContext(ctx, "kind", "load", "docker-image",
			container+":latest", "--name", env.ClusterName)
		loadCmd.Stdout = os.Stdout
		loadCmd.Stderr = os.Stderr

		if err := loadCmd.Run(); err != nil {
			return fmt.Errorf("failed to load container %s: %w", container, err)
		}
	}

	return nil
}

func (env *TestEnvironment) deployAggregator(ctx context.Context) error {
	fmt.Println("Deploying aggregator...")

	yamlFiles := []string{
		"../k8s/app/ns.yaml",
		"../k8s/app/config.yaml",
	}

	for _, yamlFile := range yamlFiles {
		applyCmd := exec.CommandContext(ctx, "kubectl", "apply", "-f", yamlFile)
		applyCmd.Stdout = os.Stdout
		applyCmd.Stderr = os.Stderr

		if err := applyCmd.Run(); err != nil {
			return fmt.Errorf("failed to apply %s: %w", yamlFile, err)
		}
	}

	applyCmd := exec.CommandContext(ctx, "sh", "-c",
		"kubectl apply -f ../k8s/app/aggregator.yaml 2>&1 | grep -v 'IngressRoute' || true")
	applyCmd.Stdout = os.Stdout
	applyCmd.Stderr = os.Stderr

	if err := applyCmd.Run(); err != nil {
		return fmt.Errorf("failed to apply aggregator.yaml: %w", err)
	}

	return nil
}

func (env *TestEnvironment) WaitForAggregatorReady(ctx context.Context) error {
	timeout := time.After(2 * time.Minute)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			return fmt.Errorf("timeout waiting for aggregator to be ready")
		case <-ticker.C:
			pods, err := env.KubeClient.CoreV1().Pods("aggregator-app").List(ctx, metav1.ListOptions{
				LabelSelector: "app=aggregator-server",
			})
			if err != nil {
				continue
			}

			if len(pods.Items) > 0 {
				pod := pods.Items[0]
				if pod.Status.Phase == "Running" {
					for _, condition := range pod.Status.Conditions {
						if condition.Type == "Ready" && condition.Status == "True" {
							return nil
						}
					}
				}
			}
		}
	}
}

func (env *TestEnvironment) SetupPortForward(ctx context.Context) error {
	fmt.Println("Setting up port forward...")

	pods, err := env.KubeClient.CoreV1().Pods("aggregator-app").List(ctx, metav1.ListOptions{
		LabelSelector: "app=aggregator-server",
	})
	if err != nil {
		return fmt.Errorf("failed to list pods: %w", err)
	}

	if len(pods.Items) == 0 {
		return fmt.Errorf("no aggregator-server pods found")
	}

	podName := pods.Items[0].Name

	env.portForwardCmd = exec.Command("kubectl", "port-forward",
		"-n", "aggregator-app",
		"pod/"+podName,
		"8080:5000")
	env.portForwardCmd.Stdout = os.Stdout
	env.portForwardCmd.Stderr = os.Stderr

	if err := env.portForwardCmd.Start(); err != nil {
		return fmt.Errorf("failed to start port forward: %w", err)
	}

	time.Sleep(2 * time.Second)

	fmt.Println("Port forward established on localhost:8080")
	return nil
}

func (env *TestEnvironment) Cleanup() error {
	fmt.Println("Cleaning up test environment...")

	var errors []error

	if env.portForwardCmd != nil && env.portForwardCmd.Process != nil {
		fmt.Println("Stopping port forward...")
		if err := env.portForwardCmd.Process.Kill(); err != nil {
			errors = append(errors, fmt.Errorf("failed to stop port forward: %w", err))
		}
	}

	if env.umaServerProcess != nil && env.umaServerProcess.Process != nil {
		fmt.Println("Stopping UMA server...")
		if err := env.umaServerProcess.Process.Kill(); err != nil {
			errors = append(errors, fmt.Errorf("failed to stop UMA server: %w", err))
		}
	}

	for i := len(env.cleanupFuncs) - 1; i >= 0; i-- {
		if err := env.cleanupFuncs[i](); err != nil {
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		fmt.Printf("Cleanup completed with %d error(s)\n", len(errors))
		return errors[0]
	}

	fmt.Println("Cleanup completed successfully")
	return nil
}
