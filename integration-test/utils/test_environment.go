package utils

import (
	"context"
	"fmt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"os/exec"
	"strings"
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
		ClusterName:   "aggregator",
		AggregatorURL: "http://aggregator.local",
	}

	// Check if cluster exists
	cmd := exec.CommandContext(ctx, "kind", "get", "clusters")
	output, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(output), env.ClusterName) {
		return nil, fmt.Errorf("kind cluster '%s' not found. Please run 'make init' first", env.ClusterName)
	}

	if err := env.setupKubeClient(); err != nil {
		return nil, fmt.Errorf("failed to setup kubernetes client: %w", err)
	}

	// Check if aggregator is deployed
	if err := env.checkAggregatorDeployed(ctx); err != nil {
		return nil, fmt.Errorf("aggregator not deployed: %w. Please run 'make deploy' first", err)
	}

	return env, nil
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

func (env *TestEnvironment) checkAggregatorDeployed(ctx context.Context) error {
	// Check if aggregator-app namespace exists
	_, err := env.KubeClient.CoreV1().Namespaces().Get(ctx, "aggregator-app", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("aggregator-app namespace not found: %w", err)
	}

	// Check if aggregator-server deployment exists and is ready
	deployment, err := env.KubeClient.AppsV1().Deployments("aggregator-app").Get(ctx, "aggregator-server", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("aggregator-server deployment not found: %w", err)
	}

	if deployment.Status.ReadyReplicas == 0 {
		return fmt.Errorf("aggregator-server has no ready replicas")
	}

	fmt.Println("Found existing aggregator deployment")
	return nil
}

func (env *TestEnvironment) Cleanup() error {
	fmt.Println("Cleaning up test environment...")

	var errors []error

	if env.umaServerProcess != nil && env.umaServerProcess.Process != nil {
		fmt.Println("Stopping UMA server...")
		if err := env.umaServerProcess.Process.Kill(); err != nil {
			errors = append(errors, fmt.Errorf("failed to stop UMA server: %w", err))
		}
	}

	// Note: We don't delete the cluster as it's shared with the main deployment
	// The user should run 'make clean' to remove everything

	if len(errors) > 0 {
		fmt.Printf("Cleanup completed with %d error(s)\n", len(errors))
		return errors[0]
	}

	fmt.Println("Test cleanup complete (cluster left running)")
	return nil
}
