package main

import (
	"context"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func waitForIngressUMA(ctx context.Context) error {
	config, err := rest.InClusterConfig()
	if err != nil {
		return err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	for {
		pods, err := clientset.CoreV1().Pods(Namespace).List(ctx, metav1.ListOptions{
			LabelSelector: "app.kubernetes.io/component=ingress-uma",
		})
		if err != nil {
			return err
		}

		running := 0
		for _, p := range pods.Items {
			if p.Status.Phase == "Running" {
				running++
			}
		}

		if running == 0 {
			break
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(1 * time.Second):
		}
	}

	return nil
}
