package main

import (
	"context"
	"fmt"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"net/http"
	"time"
)

const (
	cleanupDaemonName      = "cleanup-daemon"
	cleanupDaemonNamespace = "default"
	cleanupDaemonPort      = 9999
)

func DeployCleanupDaemon() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logrus.Info("🚀 Deploying cleanup daemon...")

	if err := deleteExistingCleanupDaemon(ctx); err != nil {
		return err
	}

	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: cleanupDaemonName,
			Labels: map[string]string{
				"app": cleanupDaemonName,
			},
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:            cleanupDaemonName,
					Image:           "cleanup-daemon",
					ImagePullPolicy: v1.PullNever,
					Env: []v1.EnvVar{
						{Name: "NAMESPACE", Value: cleanupDaemonNamespace},
						{Name: "PORT", Value: fmt.Sprintf("%d", cleanupDaemonPort)},
						{Name: "LOG_LEVEL", Value: LogLevel.String()},
					},
					Ports: []v1.ContainerPort{
						{ContainerPort: cleanupDaemonPort},
					},
				},
			},
			RestartPolicy: v1.RestartPolicyNever,
		},
	}

	_, err := Clientset.CoreV1().Pods(cleanupDaemonNamespace).Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create cleanup daemon pod: %w", err)
	}

	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: cleanupDaemonName,
		},
		Spec: v1.ServiceSpec{
			Selector: map[string]string{
				"app": cleanupDaemonName,
			},
			Ports: []v1.ServicePort{
				{
					Port:       cleanupDaemonPort,
					TargetPort: intstr.FromInt32(cleanupDaemonPort),
				},
			},
		},
	}

	_, err = Clientset.CoreV1().Services(cleanupDaemonNamespace).Create(ctx, service, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create cleanup daemon service: %w", err)
	}

	watcher, err := Clientset.CoreV1().Pods(cleanupDaemonNamespace).Watch(ctx, metav1.ListOptions{
		FieldSelector: fmt.Sprintf("metadata.name=%s", cleanupDaemonName),
	})
	if err != nil {
		return fmt.Errorf("failed to watch cleanup daemon pod: %w", err)
	}

	logrus.Info("⏳ Waiting for cleanup daemon to be ready...")
	timeout := time.After(30 * time.Second)
	for {
		select {
		case event := <-watcher.ResultChan():
			if event.Object == nil {
				continue
			}
			pod := event.Object.(*v1.Pod)
			if pod.Status.Phase == v1.PodRunning {
				logrus.Info("✅ Cleanup daemon is ready")
				return nil
			} else if pod.Status.Phase == v1.PodFailed {
				return fmt.Errorf("cleanup daemon pod failed to start: %v", pod.Status.Reason)
			}
		case <-timeout:
			return fmt.Errorf("timeout waiting for cleanup daemon to start")
		}
	}
}

func deleteExistingCleanupDaemon(ctx context.Context) error {
	gracePeriod := int64(0)
	foundExisting := false

	if err := Clientset.CoreV1().Pods(cleanupDaemonNamespace).Delete(ctx, cleanupDaemonName, metav1.DeleteOptions{
		GracePeriodSeconds: &gracePeriod,
	}); err != nil {
		if !apierrors.IsNotFound(err) {
			logrus.WithFields(logrus.Fields{"err": err}).Warn("Failed to delete old cleanup daemon pod")
		}
	} else {
		foundExisting = true
	}

	if err := Clientset.CoreV1().Services(cleanupDaemonNamespace).Delete(ctx, cleanupDaemonName, metav1.DeleteOptions{}); err != nil {
		if !apierrors.IsNotFound(err) {
			logrus.WithFields(logrus.Fields{"err": err}).Warn("Failed to delete old cleanup daemon service")
		}
	} else {
		foundExisting = true
	}

	if foundExisting {
		logrus.Info("Cleanup daemon already exists, deleting old instance...")
	}

	return waitForCleanupDaemonDeletion(ctx)
}

func waitForCleanupDaemonDeletion(ctx context.Context) error {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	for {
		podDeleted, err := cleanupDaemonPodDeleted(ctx)
		if err != nil {
			return err
		}
		serviceDeleted, err := cleanupDaemonServiceDeleted(ctx)
		if err != nil {
			return err
		}
		if podDeleted && serviceDeleted {
			return nil
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for old cleanup daemon resources to be deleted: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func cleanupDaemonPodDeleted(ctx context.Context) (bool, error) {
	_, err := Clientset.CoreV1().Pods(cleanupDaemonNamespace).Get(ctx, cleanupDaemonName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to check cleanup daemon pod deletion: %w", err)
	}
	return false, nil
}

func cleanupDaemonServiceDeleted(ctx context.Context) (bool, error) {
	_, err := Clientset.CoreV1().Services(cleanupDaemonNamespace).Get(ctx, cleanupDaemonName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to check cleanup daemon service deletion: %w", err)
	}
	return false, nil
}

func TriggerCleanup() {
	cleanupURL := fmt.Sprintf("http://%s.%s.svc.cluster.local:%d/cleanup",
		cleanupDaemonName, cleanupDaemonNamespace, cleanupDaemonPort)

	logrus.WithFields(logrus.Fields{"url": cleanupURL}).Info("🧹 Triggering cleanup daemon")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", cleanupURL, nil)
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Warn("Failed to create cleanup request, falling back to inline cleanup")
		performInlineCleanup()
		return
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Warn("Failed to trigger cleanup daemon, falling back to inline cleanup")
		performInlineCleanup()
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusAccepted {
		logrus.Info("✅ Cleanup daemon triggered successfully - resources will be cleaned up")
	} else {
		logrus.WithFields(logrus.Fields{"status": resp.StatusCode}).Warn("Unexpected cleanup daemon response, falling back to inline cleanup")
		performInlineCleanup()
	}
}
