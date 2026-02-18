package utils

import (
	"aggregator-integration-test/mocks"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type TestEnvironment struct {
	KubeClient                *kubernetes.Clientset
	AggregatorServerURL       string
	TransformationCatalogPath string
	RegistrationPath          string
	ServiceCollectionPath     string
	ClientIDPath              string
	ResourceServerUrl         string
	ClusterName               string
	Namespace                 string
	ClientID                  string
	ClientSecret              string
	ProvisionClientID         string
	ProvisionClientSecret     string
	cleanupFuncs              []func() error
	UMAServer                 *mocks.UMAAuthorizationServer
	OIDCServer                *mocks.OIDCProvider
}

type ServiceConfig struct {
	ID          string
	Name        string
	Description string
}

type UserConfig struct {
	Username string
	Email    string
	Password string
}

type Service struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

func SetupTestEnvironment(ctx context.Context) (*TestEnvironment, error) {
	env := &TestEnvironment{
		ClusterName:               "aggregator",
		AggregatorServerURL:       "http://aggregator.local:5080",
		TransformationCatalogPath: "/transformations",
		RegistrationPath:          "/registration",
		ServiceCollectionPath:     "/services",
		ClientIDPath:              "/client.jsonld",
		Namespace:                 "aggregator-platform-test",
		ClientID:                  "aggregator-server",
		ClientSecret:              "aggregator-server-secret",
		ProvisionClientID:         "provision-client-id",
		ProvisionClientSecret:     "provision-client-secret",
	}

	// Check if cluster exists
	output, err := run(ctx, "kind", "get", "clusters")
	if err != nil || !strings.Contains(string(output), env.ClusterName) {
		return nil, fmt.Errorf("kind cluster '%s' not found. Please run 'make init' first", env.ClusterName)
	}

	if err := env.setupKubeClient(); err != nil {
		return nil, fmt.Errorf("failed to setup kubernetes client: %w", err)
	}

	// Ensure aggregator.local & test.local resolve to 127.0.0.1
	if err := env.ensureHostsEntry("aggregator.local"); err != nil {
		return nil, fmt.Errorf("failed to setup /etc/hosts entry: %w\n\nPlease manually add:\n  127.0.0.1 aggregator.local\nOr run:\n  echo '127.0.0.1 aggregator.local' | sudo tee -a /etc/hosts", err)
	}

	// Ensure cluster is configured for tests (Traefik)
	if err := env.ensureClusterConfiguration(ctx); err != nil {
		return nil, fmt.Errorf("failed to ensure cluster configuration: %w", err)
	}

	// Ensure aggregator is deployed with test config
	if err := env.ensureTestDeployment(ctx); err != nil {
		return nil, fmt.Errorf("failed to ensure test deployment: %w", err)
	}

	// Ensure mocks are running
	if err := env.ensureMocks(); err != nil {
		return nil, err
	}

	return env, nil
}

// ensureHostsEntry ensures hostname resolves to 127.0.0.1
func (env *TestEnvironment) ensureHostsEntry(hostname string) error {
	// Check if already exists
	checkCmd := exec.Command("grep", "-q", "^127.0.0.1.*"+hostname, "/etc/hosts")
	if err := checkCmd.Run(); err == nil {
		// Already exists
		fmt.Println("✓ " + hostname + " DNS entry already configured")
		return nil
	}

	// Try to add it (requires sudo)
	fmt.Println("📝 Adding " + hostname + " to /etc/hosts (requires sudo)...")
	addCmd := exec.Command("sudo", "sh", "-c", "echo '127.0.0.1 "+hostname+"' >> /etc/hosts")
	addCmd.Stdin = nil
	addCmd.Stdout = nil
	addCmd.Stderr = nil

	if err := addCmd.Run(); err != nil {
		return fmt.Errorf("failed to add hosts entry (sudo required): %w", err)
	}

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

func (env *TestEnvironment) ensureClusterConfiguration(ctx context.Context) error {
	// Ensure traefik is running (required for ingress)
	if err := env.ensureTraefikRunning(ctx); err != nil {
		return fmt.Errorf("Traefik is required but not running: %w\n\nPlease run:\n  make kind-start-traefik", err)
	}

	return nil
}

// ensureTraefikRunning checks if Traefik is deployed and starts it if needed
func (env *TestEnvironment) ensureTraefikRunning(ctx context.Context) error {
	// Check if Traefik deployment exists in aggregator-traefik namespace (not "traefik")
	_, err := env.KubeClient.AppsV1().Deployments("aggregator-traefik").Get(ctx, "aggregator-traefik", metav1.GetOptions{})
	if err != nil {
		// Traefik not found, need to install it
		fmt.Println("📦 Traefik not found, installing...")
		if err := env.installTraefik(ctx); err != nil {
			return fmt.Errorf("failed to install Traefik: %w", err)
		}
	}

	// Check if traefik pods are running
	pods, err := env.KubeClient.CoreV1().Pods("aggregator-traefik").List(ctx, metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/name=traefik",
	})
	if err != nil || len(pods.Items) == 0 {
		return fmt.Errorf("no Traefik pods found after installation")
	}

	// Check if at least one pod is ready
	ready := false
	for _, pod := range pods.Items {
		for _, condition := range pod.Status.Conditions {
			if condition.Type == "Ready" && condition.Status == "True" {
				ready = true
				break
			}
		}
		if ready {
			break
		}
	}

	if !ready {
		fmt.Println("⏳ Waiting for Traefik to be ready...")
		// Wait for Traefik to be ready
		_, err := run(ctx, "kubectl", "wait",
			"--for=condition=ready",
			"--timeout=60s",
			"pod",
			"-l", "app.kubernetes.io/name=traefik",
			"-n", "aggregator-traefik")
		if err != nil {
			return fmt.Errorf("timeout waiting for Traefik to be ready: %w", err)
		}
	}

	fmt.Println("✓ Traefik is running")
	return nil
}

// installTraefik installs Traefik using helm with the same configuration as make kind-start-traefik
func (env *TestEnvironment) installTraefik(ctx context.Context) error {
	fmt.Println("🚀 Installing Traefik with Helm...")

	// Add traefik helm repo
	if _, err := run(ctx,
		"helm", "repo", "add",
		"traefik", "https://traefik.github.io/charts",
	); err != nil {
		// Allow "already exists" case
		if !strings.Contains(err.Error(), "already exists") {
			return fmt.Errorf("failed to add Traefik helm repo: %w", err)
		}
	}

	// Update helm repos
	if _, err := run(ctx, "helm", "repo", "update"); err != nil {
		return fmt.Errorf("failed to update helm repos: %w", err)
	}

	// Install / upgrade Traefik
	if _, err := run(ctx,
		"helm", "upgrade", "--install", "aggregator-traefik", "traefik/traefik",
		"--namespace", "aggregator-traefik",
		"--create-namespace",
		"--set", "ingressClass.enabled=true",
		"--set", "ingressClass.name=aggregator-traefik",
		"--set", "ports.web.hostPort=80",
		"--set", "ports.websecure.hostPort=443",
		"--set", "service.type=ClusterIP",
	); err != nil {
		return fmt.Errorf("failed to install Traefik: %w", err)
	}

	// Wait for deployment rollout
	fmt.Println("⏳ Waiting for Traefik deployment...")
	if _, err := run(ctx,
		"kubectl", "rollout", "status",
		"deployment/aggregator-traefik",
		"-n", "aggregator-traefik",
		"--timeout=180s",
	); err != nil {
		return fmt.Errorf("timeout waiting for Traefik deployment: %w", err)
	}

	fmt.Println("✅ Traefik installed successfully")
	return nil
}

// ensureTestDeployment checks if aggregator is deployed with test config and deploys if needed
func (env *TestEnvironment) ensureTestDeployment(ctx context.Context) error {
	// Deploy with test config using kubectl
	fmt.Println("📄 Deploying aggregator application...")

	// Helm upgrade/install
	if _, err := run(ctx,
		"helm", "upgrade", "--install",
		env.Namespace, "../aggregator-platform",
		"-f", "./config/helm-test.yaml",
		"-n", env.Namespace,
		"--create-namespace",
	); err != nil {
		return fmt.Errorf("failed to deploy aggregator-platform: %w", err)
	}

	// Wait for deployment rollout
	if _, err := run(ctx,
		"kubectl", "rollout", "status",
		"deployment/aggregator-server",
		"-n", env.Namespace,
		"--timeout=120s",
	); err != nil {
		return fmt.Errorf("aggregator-server deployment did not become ready: %w", err)
	}

	fmt.Println("✅ Aggregator application successfully deployed!")

	// Health check: verify aggregator is responding via Traefik
	fmt.Println("🔍 Verifying aggregator is responding...")
	for i := 0; i < 10; i++ {
		checkURL := strings.TrimRight(env.AggregatorServerURL, "/") + "/"
		_, err := run(ctx, "curl", "-sf", checkURL)
		if err == nil {
			fmt.Println("✅ Aggregator is responding via Traefik")
			break
		}
		if i == 9 {
			fmt.Println("⚠️  Warning: Aggregator health check failed, but continuing anyway")
		}
		time.Sleep(2 * time.Second)
	}

	fmt.Println("✅ Aggregator deployed with test configuration")
	return nil
}

func (env *TestEnvironment) ensureMocks() error {
	env.UMAServer = mocks.NewUMAAuthorizationServer()
	oidc, err := mocks.NewOIDCProvider()
	if err != nil {
		return fmt.Errorf("Failed to start OIDC Provider: %w", err)
	}
	env.OIDCServer = oidc
	return nil
}

func (env *TestEnvironment) Cleanup() error {
	fmt.Println("Cleaning up test environment...")

	var errors []error

	// Stop the mock services
	env.UMAServer.Close()
	env.OIDCServer.Close()

	_, err := run(context.Background(), "helm", "uninstall", env.Namespace, "-n", env.Namespace)
	if err != nil {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		fmt.Printf("Cleanup completed with %d error(s)\n", len(errors))
		return errors[0]
	}

	fmt.Println("Test cleanup complete (cluster left running)")
	return nil
}

func run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("command failed: %s %v\n%s",
			name, args, string(output))
	}
	return output, nil
}
