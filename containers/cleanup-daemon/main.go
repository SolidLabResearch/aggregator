package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func getEnv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func main() {
	namespace := flag.String("namespace", getEnv("NAMESPACE", "default"), "Kubernetes namespace to clean up")
	port := flag.String("port", getEnv("PORT", "9999"), "Port to listen on")
	logLevel := flag.String("log-level", getEnv("LOG_LEVEL", "info"), "Log level")
	flag.Parse()

	parsedLevel, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		parsedLevel = logrus.InfoLevel
	}
	logrus.SetLevel(parsedLevel)
	logrus.SetOutput(os.Stdout)

	var kubeCfg *rest.Config
	var kubeErr error

	if strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST")) != "" {
		kubeCfg, kubeErr = rest.InClusterConfig()
		if kubeErr != nil {
			logrus.WithError(kubeErr).Warn("In-cluster config not available, trying KUBECONFIG")
		}
	}

	if kubeCfg == nil {
		kubeconfigPath := getEnv("KUBECONFIG", filepath.Join(homedir.HomeDir(), ".kube", "config"))
		kubeCfg, kubeErr = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	}

	if kubeCfg == nil || kubeErr != nil {
		logrus.WithError(kubeErr).Fatal("No Kubernetes configuration found")
	}

	clientset, err := kubernetes.NewForConfig(kubeCfg)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create Kubernetes client")
	}

	logrus.WithFields(logrus.Fields{
		"namespace": *namespace,
		"port":      *port,
	}).Info("🚀 Starting cleanup daemon")

	daemon := NewCleanupDaemon(clientset, *namespace, *port)
	daemon.Start()
}

// CleanupDaemon handles graceful cleanup of Kubernetes resources
type CleanupDaemon struct {
	clientset *kubernetes.Clientset
	namespace string
	port      string
}

func NewCleanupDaemon(clientset *kubernetes.Clientset, namespace, port string) *CleanupDaemon {
	if namespace == "" {
		namespace = "default"
	}
	if port == "" {
		port = "9999"
	}
	return &CleanupDaemon{
		clientset: clientset,
		namespace: namespace,
		port:      port,
	}
}

func (cd *CleanupDaemon) Start() {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK")
	})

	mux.HandleFunc("/cleanup", cd.handleCleanup)

	logrus.WithFields(logrus.Fields{"port": cd.port}).Info("🧹 Cleanup daemon listening")
	if err := http.ListenAndServe(":"+cd.port, mux); err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("Cleanup daemon server failed")
		os.Exit(1)
	}
}

func (cd *CleanupDaemon) handleCleanup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	logrus.Info("🧹 Cleanup requested - starting resource deletion")
	w.WriteHeader(http.StatusAccepted)
	fmt.Fprintf(w, "Cleanup started\n")

	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	go cd.performCleanup()
}

func (cd *CleanupDaemon) performCleanup() {
	ctx := context.Background()

	logrus.Info("🧹 Deleting pods...")
	if err := cd.deletePods(ctx); err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("Failed to delete all pods")
	}

	logrus.Info("🧹 Deleting services...")
	if err := cd.deleteServices(ctx); err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("Failed to delete all services")
	}

	logrus.Info("✅ Cleanup complete - daemon will exit in 5 seconds")
	time.Sleep(5 * time.Second)
	os.Exit(0)
}

func (cd *CleanupDaemon) deletePods(ctx context.Context) error {
	maxRetries := 3

	for attempt := 1; attempt <= maxRetries; attempt++ {
		pods, err := cd.clientset.CoreV1().Pods(cd.namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("failed to list pods: %w", err)
		}

		if len(pods.Items) == 0 {
			logrus.Info("✅ All pods deleted")
			return nil
		}

		logrus.WithFields(logrus.Fields{
			"count":   len(pods.Items),
			"attempt": attempt,
		}).Info("Deleting pods")

		var wg sync.WaitGroup
		sem := make(chan struct{}, 30)

		for _, pod := range pods.Items {
			p := pod
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				deleteCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				defer cancel()

				gracePeriod := int64(0)
				err := cd.clientset.CoreV1().Pods(p.Namespace).Delete(deleteCtx, p.Name, metav1.DeleteOptions{
					GracePeriodSeconds: &gracePeriod,
				})
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"namespace": p.Namespace,
						"name":      p.Name,
						"err":       err,
					}).Warn("Failed to delete pod")
				} else {
					logrus.WithFields(logrus.Fields{
						"namespace": p.Namespace,
						"name":      p.Name,
					}).Debug("Deleted pod")
				}
			}()
		}

		wg.Wait()

		if attempt < maxRetries {
			logrus.Info("⏳ Waiting for pods to terminate...")
			time.Sleep(5 * time.Second)
		}
	}

	pods, err := cd.clientset.CoreV1().Pods(cd.namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	if len(pods.Items) > 0 {
		logrus.WithFields(logrus.Fields{"remaining": len(pods.Items)}).Warn("⚠️  Some pods could not be deleted")
		for _, pod := range pods.Items {
			logrus.WithFields(logrus.Fields{
				"name":   pod.Name,
				"status": pod.Status.Phase,
			}).Warn("Remaining pod")
		}
	}

	return nil
}

func (cd *CleanupDaemon) deleteServices(ctx context.Context) error {
	services, err := cd.clientset.CoreV1().Services(cd.namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list services: %w", err)
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 30)

	for _, svc := range services.Items {
		if svc.Name == "kubernetes" || svc.Name == "cleanup-daemon" {
			continue
		}

		s := svc
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			deleteCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()

			err := cd.clientset.CoreV1().Services(s.Namespace).Delete(deleteCtx, s.Name, metav1.DeleteOptions{})
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"namespace": s.Namespace,
					"name":      s.Name,
					"err":       err,
				}).Warn("Failed to delete service")
			} else {
				logrus.WithFields(logrus.Fields{
					"namespace": s.Namespace,
					"name":      s.Name,
				}).Debug("Deleted service")
			}
		}()
	}

	wg.Wait()
	logrus.Info("✅ All services deleted")
	return nil
}
