package main

import (
	"context"
	"flag"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

func main() {
	var aggregatorNS string
	flag.StringVar(&aggregatorNS, "ns", "aggregator-app", "Namespace to watch for deletion")
	flag.Parse()

	// Create in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		logrus.Fatalf("Failed to load in-cluster config: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		logrus.Fatalf("Failed to create clientset: %v", err)
	}

	// Watch namespaces
	watchNamespaces(clientset, aggregatorNS)
}

func watchNamespaces(clientset *kubernetes.Clientset, aggregatorNS string) {
	watchlist := cache.NewListWatchFromClient(
		clientset.CoreV1().RESTClient(),
		"namespaces",
		metav1.NamespaceAll,
		fields.Everything(),
	)

	_, controller := cache.NewInformer(
		watchlist,
		&corev1.Namespace{},
		0, // no resync
		cache.ResourceEventHandlerFuncs{
			DeleteFunc: func(obj interface{}) {
				ns, ok := obj.(*corev1.Namespace)
				if !ok {
					logrus.Warn("DeleteFunc received non-namespace object")
					return
				}
				if ns.Name == aggregatorNS {
					logrus.Infof("Aggregator namespace '%s' deleted. Starting cleanup...", aggregatorNS)
					cleanupNamespaces(clientset)
				}
			},
		},
	)

	stop := make(chan struct{})
	defer close(stop)
	logrus.Infof("Watching for deletion of namespace: %s", aggregatorNS)
	controller.Run(stop)
}

func cleanupNamespaces(clientset *kubernetes.Clientset) {
	ctx := context.Background()

	nsList, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{
		LabelSelector: "created-by=aggregator",
	})
	if err != nil {
		logrus.Errorf("Failed to list namespaces: %v", err)
		return
	}

	for _, ns := range nsList.Items {
		logrus.Infof("Deleting namespace: %s", ns.Name)
		err := clientset.CoreV1().Namespaces().Delete(ctx, ns.Name, metav1.DeleteOptions{})
		if err != nil {
			logrus.Errorf("Failed to delete namespace %s: %v", ns.Name, err)
		}
	}

	logrus.Infof("Cleanup complete. Total deleted: %d", len(nsList.Items))
}
