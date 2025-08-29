package main

import (
	"aggregator/auth"
	"aggregator/proxy"
	"golang.org/x/net/context"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

var Protocol = "http"
var Host = "localhost"
var ServerPort = "5000"

var Clientset *kubernetes.Clientset

func main() {
	config, err := clientcmd.BuildConfigFromFlags("", filepath.Join(homedir.HomeDir(), ".kube", "config"))
	if err != nil {
		log.Fatalf("Failed to load Kubernetes config: %v", err)
	}
	Clientset, err = kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create Kubernetes client: %v", err)
	}
	proxy.SetupProxy(Clientset)

	serverMux := http.NewServeMux()
	go func() {
		log.Println("Server listening on port: " + ServerPort)
		log.Fatal(http.ListenAndServe(":"+ServerPort, serverMux))
	}()
	auth.InitSigning(serverMux)
	InitializeKubernetes(serverMux)
	startConfigurationEndpoint(serverMux)
	SetupResourceRegistration()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	<-stop // wait for signal
	log.Println("Shutting down gracefully...")
	// remove all pods (including proxy?)
	pods, err := Clientset.CoreV1().Pods("default").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Fatal(err)
	}

	for _, pod := range pods.Items {
		err := Clientset.CoreV1().Pods(pod.Namespace).Delete(context.Background(), pod.Name, metav1.DeleteOptions{})
		if err != nil {
			log.Printf("Failed to delete pod %s/%s: %v", pod.Namespace, pod.Name, err)
		} else {
			log.Printf("Deleted pod: %s/%s", pod.Namespace, pod.Name)
		}
	}

	services, err := Clientset.CoreV1().Services("default").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Fatal(err)
	}

	for _, svc := range services.Items {
		// Skip the critical Kubernetes API service
		if svc.Name == "kubernetes" {
			continue
		}
		err := Clientset.CoreV1().Services(svc.Namespace).Delete(context.Background(), svc.Name, metav1.DeleteOptions{})
		if err != nil {
			log.Printf("Failed to delete service %s/%s: %v", svc.Namespace, svc.Name, err)
		} else {
			log.Printf("Deleted service: %s/%s", svc.Namespace, svc.Name)
		}
	}

	log.Println("Cleanup complete. Exiting.")

	// let AS know that all resources need to be deleted
	auth.DeleteAllResources()
}
