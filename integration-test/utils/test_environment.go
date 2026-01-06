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
	MockOIDCHost      string
	cleanupFuncs      []func() error
	umaServerProcess  *exec.Cmd
	portForwardCmd    *exec.Cmd
	proxyServer       *exec.Cmd
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

	if err := env.configureMockOIDCHost(ctx); err != nil {
		return nil, fmt.Errorf("failed to configure mock OIDC host: %w", err)
	}

	if env.shouldUseOIDCProxy() {
		// Start reverse proxy on port 80 to forward oidc.local requests
		if err := env.startReverseProxy(ctx); err != nil {
			return nil, fmt.Errorf("failed to start reverse proxy: %w", err)
		}
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

	// Ensure aggregator.local resolves to 127.0.0.1
	if err := env.ensureHostsEntry(); err != nil {
		return nil, fmt.Errorf("failed to setup /etc/hosts entry: %w\n\nPlease manually add:\n  127.0.0.1 aggregator.local\n\nOr run:\n  echo '127.0.0.1 aggregator.local' | sudo tee -a /etc/hosts", err)
	}

	if env.shouldUseOIDCProxy() {
		if err := env.ensureOIDCHostEntry(); err != nil {
			return nil, fmt.Errorf("failed to setup oidc.local entry: %w", err)
		}
	}

	// Ensure aggregator is deployed with test config
	if err := env.ensureTestDeployment(ctx); err != nil {
		return nil, fmt.Errorf("failed to ensure test deployment: %w", err)
	}

	return env, nil
}

func (env *TestEnvironment) configureMockOIDCHost(ctx context.Context) error {
	if existing := strings.TrimSpace(os.Getenv("MOCK_OIDC_HOST")); existing != "" {
		env.MockOIDCHost = existing
		fmt.Printf("✓ Using MOCK_OIDC_HOST=%s for mock OIDC issuer\n", existing)
		return nil
	}

	gatewayIP, err := env.getKindGatewayIP(ctx)
	if err != nil {
		fmt.Printf("⚠️  Unable to determine Kind gateway IP, falling back to oidc.local: %v\n", err)
		return nil
	}

	env.MockOIDCHost = gatewayIP
	if err := os.Setenv("MOCK_OIDC_HOST", gatewayIP); err != nil {
		return fmt.Errorf("failed to set MOCK_OIDC_HOST: %w", err)
	}

	fmt.Printf("✓ Using Kind gateway IP %s for mock OIDC issuer\n", gatewayIP)
	return nil
}

func (env *TestEnvironment) shouldUseOIDCProxy() bool {
	return env.MockOIDCHost == "" || env.MockOIDCHost == "oidc.local"
}

func (env *TestEnvironment) getKindGatewayIP(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", "network", "inspect", "kind", "--format", "{{range .IPAM.Config}}{{.Gateway}} {{end}}")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to inspect kind network: %w (output: %s)", err, strings.TrimSpace(string(output)))
	}

	fields := strings.Fields(string(output))
	if len(fields) == 0 {
		return "", fmt.Errorf("kind network gateway IP is empty")
	}

	for _, gateway := range fields {
		if strings.Count(gateway, ".") == 3 {
			return gateway, nil
		}
	}

	return fields[0], nil
}

// verifyTestConfig checks that the aggregator is using test configuration
func (env *TestEnvironment) verifyTestConfig(ctx context.Context) error {
	configMap, err := env.KubeClient.CoreV1().ConfigMaps("aggregator-app").Get(ctx, "aggregator-config", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("aggregator-config ConfigMap not found: %w", err)
	}

	disableAuth, ok := configMap.Data["disable_auth"]
	if !ok {
		return fmt.Errorf("disable_auth not set in config")
	}

	if disableAuth != "true" {
		return fmt.Errorf("disable_auth=%s (expected 'true' for tests)", disableAuth)
	}

	fmt.Println("✓ Test configuration active (disable_auth=true)")
	return nil
}

// ensureHostsEntry ensures aggregator.local resolves to 127.0.0.1
func (env *TestEnvironment) ensureHostsEntry() error {
	// Check if already exists
	checkCmd := exec.Command("grep", "-q", "^127.0.0.1.*aggregator.local", "/etc/hosts")
	if err := checkCmd.Run(); err == nil {
		// Already exists
		fmt.Println("✓ aggregator.local DNS entry already configured")
		return nil
	}

	// Try to add it (requires sudo)
	fmt.Println("📝 Adding aggregator.local to /etc/hosts (requires sudo)...")
	addCmd := exec.Command("sudo", "sh", "-c", "echo '127.0.0.1 aggregator.local' >> /etc/hosts")
	addCmd.Stdin = nil
	addCmd.Stdout = nil
	addCmd.Stderr = nil

	if err := addCmd.Run(); err != nil {
		return fmt.Errorf("failed to add hosts entry (sudo required): %w", err)
	}

	fmt.Println("✅ Added aggregator.local to /etc/hosts")
	return nil
}

// ensureOIDCHostEntry ensures oidc.local resolves to 127.0.0.1
func (env *TestEnvironment) ensureOIDCHostEntry() error {
	// Check if already exists
	checkCmd := exec.Command("grep", "-q", "^127.0.0.1.*oidc.local", "/etc/hosts")
	if err := checkCmd.Run(); err == nil {
		// Already exists
		fmt.Println("✓ oidc.local DNS entry already configured")
		return nil
	}

	// Try to add it (requires sudo)
	fmt.Println("📝 Adding oidc.local to /etc/hosts (requires sudo)...")
	addCmd := exec.Command("sudo", "sh", "-c", "echo '127.0.0.1 oidc.local' >> /etc/hosts")
	addCmd.Stdin = nil
	addCmd.Stdout = nil
	addCmd.Stderr = nil

	if err := addCmd.Run(); err != nil {
		return fmt.Errorf("failed to add oidc.local entry (sudo required): %w", err)
	}

	fmt.Println("✅ Added oidc.local to /etc/hosts")
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

// ensureTestDeployment checks if aggregator is deployed with test config and deploys if needed
func (env *TestEnvironment) ensureTestDeployment(ctx context.Context) error {
	// Check if config exists and has disable_auth=true
	configMap, err := env.KubeClient.CoreV1().ConfigMaps("aggregator-app").Get(ctx, "aggregator-config", metav1.GetOptions{})
	if err == nil {
		// Config exists, check if it has disable_auth=true
		if disableAuth, ok := configMap.Data["disable_auth"]; ok && disableAuth == "true" {
			// Check if deployment is ready
			if err := env.checkAggregatorDeployed(ctx); err == nil {
				return nil // Already deployed with test config
			}
		}

		// Config exists but wrong setting or deployment not ready
		fmt.Println("⚠️  Existing deployment found with wrong config, redeploying with test config...")
	} else {
		fmt.Println("📦 No aggregator deployment found, deploying with test config...")
	}

	// Check if Traefik is running (required for ingress)
	if err := env.ensureTraefikRunning(ctx); err != nil {
		return fmt.Errorf("Traefik is required but not running: %w\n\nPlease run:\n  make kind-start-traefik", err)
	}

	// Deploy with test config using kubectl
	fmt.Println("🧪 Deploying aggregator with TEST configuration (auth disabled)...")

	// Set kubectl context
	execCmd := exec.CommandContext(ctx, "kubectl", "config", "use-context", "kind-aggregator")
	if output, err := execCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set kubectl context: %w\nOutput: %s", err, string(output))
	}

	// Apply namespace
	execCmd = exec.CommandContext(ctx, "kubectl", "apply", "-f", "../k8s/app/ns.yaml")
	if output, err := execCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to apply namespace: %w\nOutput: %s", err, string(output))
	}

	// Apply test config BEFORE deployment (deployment needs the configmap)
	execCmd = exec.CommandContext(ctx, "kubectl", "apply", "-f", "./config-test.yaml")
	if output, err := execCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to apply test config: %w\nOutput: %s", err, string(output))
	}

	// Apply traefik config (needed for ingress) - warnings are OK
	execCmd = exec.CommandContext(ctx, "kubectl", "apply", "-f", "../k8s/app/traefik-config.yaml")
	if output, err := execCmd.CombinedOutput(); err != nil {
		// Don't fail if traefik config fails, middlewares might already exist
		fmt.Printf("Note: traefik config warnings (expected if already applied): %s\n", string(output))
	}

	// Apply aggregator deployment - filter output to ignore IngressRoute warnings
	execCmd = exec.CommandContext(ctx, "kubectl", "apply", "-f", "../k8s/app/aggregator.yaml")
	output, err := execCmd.CombinedOutput()
	if err != nil {
		// Check if it's just IngressRoute errors (non-critical)
		outputStr := string(output)
		if strings.Contains(outputStr, "deployment.apps/aggregator-server created") ||
			strings.Contains(outputStr, "deployment.apps/aggregator-server configured") {
			// Deployment succeeded, IngressRoute errors are non-critical
			fmt.Printf("Note: IngressRoute warnings (expected): %s\n", outputStr)
		} else {
			return fmt.Errorf("failed to apply aggregator deployment: %w\nOutput: %s", err, outputStr)
		}
	}

	// Wait for deployment to be ready
	fmt.Println("⏳ Waiting for aggregator to be ready...")
	execCmd = exec.CommandContext(ctx, "kubectl", "wait",
		"--for=condition=available",
		"--timeout=120s",
		"deployment/aggregator-server",
		"-n", "aggregator-app")
	if err := execCmd.Run(); err != nil {
		return fmt.Errorf("timeout waiting for aggregator to be ready: %w", err)
	}

	// Also wait for pods to be ready
	execCmd = exec.CommandContext(ctx, "kubectl", "wait",
		"--for=condition=ready",
		"--timeout=120s",
		"pod",
		"-l", "app=aggregator-server",
		"-n", "aggregator-app")
	if err := execCmd.Run(); err != nil {
		return fmt.Errorf("timeout waiting for aggregator pods to be ready: %w", err)
	}

	// Give it a few more seconds for the service to be fully available
	fmt.Println("⏳ Waiting for service to be fully available...")
	time.Sleep(5 * time.Second)

	// Health check: verify aggregator is responding via Traefik
	fmt.Println("🔍 Verifying aggregator is responding...")
	for i := 0; i < 10; i++ {
		execCmd = exec.CommandContext(ctx, "curl", "-sf", "http://aggregator.local/")
		if err := execCmd.Run(); err == nil {
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
		execCmd := exec.CommandContext(ctx, "kubectl", "wait",
			"--for=condition=ready",
			"--timeout=60s",
			"pod",
			"-l", "app.kubernetes.io/name=traefik",
			"-n", "aggregator-traefik")
		if err := execCmd.Run(); err != nil {
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
	execCmd := exec.CommandContext(ctx, "helm", "repo", "add", "traefik", "https://traefik.github.io/charts")
	if output, err := execCmd.CombinedOutput(); err != nil {
		// Repo might already exist, check output
		if !strings.Contains(string(output), "already exists") {
			return fmt.Errorf("failed to add Traefik helm repo: %w\nOutput: %s", err, string(output))
		}
	}

	// Update helm repos
	execCmd = exec.CommandContext(ctx, "helm", "repo", "update")
	if err := execCmd.Run(); err != nil {
		return fmt.Errorf("failed to update helm repos: %w", err)
	}

	// Install traefik with helm - MATCHING PRODUCTION CONFIG
	execCmd = exec.CommandContext(ctx, "helm", "upgrade", "--install", "aggregator-traefik", "traefik/traefik",
		"--namespace", "aggregator-traefik",
		"--create-namespace",
		"--set", "ingressClass.enabled=true",
		"--set", "ingressClass.name=aggregator-traefik",
		"--set", "ports.web.hostPort=80",
		"--set", "ports.websecure.hostPort=443",
		"--set", "service.type=ClusterIP",
		"--set", "providers.kubernetesCRD.allowCrossNamespace=true")
	if output, err := execCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to install Traefik: %w\nOutput: %s", err, string(output))
	}

	// Wait for deployment to be ready
	fmt.Println("⏳ Waiting for Traefik deployment...")
	execCmd = exec.CommandContext(ctx, "kubectl", "rollout", "status",
		"deployment/aggregator-traefik",
		"-n", "aggregator-traefik",
		"--timeout=180s")
	if err := execCmd.Run(); err != nil {
		return fmt.Errorf("timeout waiting for Traefik deployment: %w", err)
	}

	fmt.Println("✅ Traefik installed successfully")
	return nil
}

// startReverseProxy starts a reverse proxy on port 80 to forward oidc.local to mock OIDC provider
func (env *TestEnvironment) startReverseProxy(ctx context.Context) error {
	// Check if port 80 is already in use
	checkCmd := exec.CommandContext(ctx, "sh", "-c", "netstat -tuln | grep ':80 ' || true")
	output, _ := checkCmd.CombinedOutput()
	if strings.Contains(string(output), ":80") {
		fmt.Println("✓ Port 80 already in use (proxy may already be running)")
		return nil
	}

	fmt.Println("🔄 Starting reverse proxy on port 80...")

	// Start the test-proxy.go in background
	proxyCmd := exec.CommandContext(ctx, "sudo", "go", "run", "test-proxy.go")
	proxyCmd.Dir = "." // Current directory (integration-test)

	if err := proxyCmd.Start(); err != nil {
		return fmt.Errorf("failed to start proxy: %w", err)
	}

	env.proxyServer = proxyCmd

	// Wait a bit for proxy to start
	time.Sleep(1 * time.Second)

	// Verify proxy is running
	checkCmd = exec.CommandContext(ctx, "sh", "-c", "netstat -tuln | grep ':80 '")
	if err := checkCmd.Run(); err != nil {
		return fmt.Errorf("proxy started but not listening on port 80")
	}

	fmt.Println("✅ Reverse proxy started on port 80")
	return nil
}

func (env *TestEnvironment) Cleanup() error {
	fmt.Println("Cleaning up test environment...")

	var errors []error

	// Stop reverse proxy
	if env.proxyServer != nil && env.proxyServer.Process != nil {
		fmt.Println("Stopping reverse proxy...")
		if err := env.proxyServer.Process.Kill(); err != nil {
			errors = append(errors, fmt.Errorf("failed to stop proxy: %w", err))
		}
	}

	if env.umaServerProcess != nil && env.umaServerProcess.Process != nil {
		fmt.Println("Stopping UMA server...")
		if err := env.umaServerProcess.Process.Kill(); err != nil {
			errors = append(errors, fmt.Errorf("failed to stop UMA server: %w", err))
		}
	}

	if len(errors) > 0 {
		fmt.Printf("Cleanup completed with %d error(s)\n", len(errors))
		return errors[0]
	}

	fmt.Println("Test cleanup complete (cluster left running)")
	return nil
}
