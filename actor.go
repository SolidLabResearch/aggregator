package main

import (
	"aggregator/auth"
	"fmt"
	"github.com/google/uuid"
	"golang.org/x/net/context"
	"io"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"log"
	"net/http"
	"time"
)

var serverMux *http.ServeMux

func InitializeKubernetes(mux *http.ServeMux) {
	serverMux = mux
}

type Actor struct {
	Id             string   `json:"id"`
	Sources        []string `json:"sources"`
	Transformation string   `json:"transformation"`
	pod            *v1.Pod
}

func createActor(transformation Transformation) (Actor, error) {
	id := uuid.New().String()

	// start an RDF-connect docker process with the transformation
	podScafolding := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: id,
			Labels: map[string]string{
				"app": id, // Important for service selector!
			},
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:  "transformation",
					Image: "file-server",
					//Image:   "rdfconnect/rdf-connect:latest",
					//Command: transformation.Transformation,
					ImagePullPolicy: v1.PullNever,
					Env: []v1.EnvVar{
						{Name: "FILE_URLS", Value: fmt.Sprintf("%v", transformation.Sources)},
						{Name: "http_proxy", Value: "http://uma-proxy-service.default.svc.cluster.local:5050"},
						{Name: "https_proxy", Value: "http://uma-proxy-service.default.svc.cluster.local:5050"},
						//{Name: "no_proxy", Value: "localhost,127.0.0.1,.svc,.cluster.local"}, // Optional
					},
					Ports: []v1.ContainerPort{
						{ContainerPort: 8080}, // Match with service
					},
				},
			},
			RestartPolicy: v1.RestartPolicyNever,
		},
	}

	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	pod, err := Clientset.CoreV1().Pods("default").Create(ctx, podScafolding, metav1.CreateOptions{})

	serviceName := "id-" + id + "-service"
	svc := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: serviceName,
		},
		Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeNodePort, // Or NodePort if you want external access
			Selector: map[string]string{
				"app": id, // Matches pod's label
			},
			Ports: []v1.ServicePort{
				{
					Port:       80,                   // The port your client will use
					TargetPort: intstr.FromInt(8080), // The port inside the pod
				},
			},
		},
	}

	_, err = Clientset.CoreV1().Services("default").Create(ctx, svc, metav1.CreateOptions{})

	if err != nil {
		return Actor{}, fmt.Errorf("failed to create pod: %v", err)
	}

	watcher, _ := Clientset.CoreV1().Pods("default").Watch(ctx, metav1.ListOptions{
		FieldSelector: fmt.Sprintf("metadata.name=%s", id),
	})

	nodes, err := Clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Fatal(err)
	}

	nodeIp := ""
	for _, node := range nodes.Items {
		for _, addr := range node.Status.Addresses {
			if addr.Type == v1.NodeExternalIP || addr.Type == v1.NodeInternalIP {
				nodeIp = addr.Address
				break
			}
		}
	}

	svc, err = Clientset.CoreV1().Services("default").Get(context.Background(), serviceName, metav1.GetOptions{})
	if err != nil {
		return Actor{}, err
	}

	nodePort := 0
	for _, port := range svc.Spec.Ports {
		if svc.Spec.Type == v1.ServiceTypeNodePort {
			nodePort = int(port.NodePort)
		}
	}

	if nodePort == 0 {
		return Actor{}, fmt.Errorf("no NodePort found for service %s", serviceName)
	}

	for event := range watcher.ResultChan() {
		pod := event.Object.(*v1.Pod)
		if pod.Status.Phase == v1.PodRunning {
			break
		} else if pod.Status.Phase == v1.PodFailed {
			return Actor{}, fmt.Errorf("pod failed to start: %v", pod.Status.Reason)
		}
	}

	fmt.Println("Pod is running on:", fmt.Sprintf("http://%s:%d", nodeIp, nodePort))

	serverMux.HandleFunc("/"+id, func(w http.ResponseWriter, r *http.Request) {
		if !auth.AuthorizeRequest(w, r, nil) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Forward the request (can also copy headers, method, etc.)
		resp, err := http.Get(fmt.Sprintf("http://%s:%d", nodeIp, nodePort))
		if err != nil {
			fmt.Println("Error reaching pod service:", err.Error())
			http.Error(w, "Failed to reach pod service", http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		// Copy response back to client
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	})

	actor := Actor{
		Id:             id,
		Sources:        transformation.Sources,
		Transformation: transformation.Transformation,
		pod:            pod,
	}

	return actor, nil
}

func (actor Actor) marshalActor() string {
	actorJson := fmt.Sprintf(
		"{id:%s,transformation:%s,sources:%v}",
		actor.Id,
		actor.Transformation,
		actor.Sources,
	)
	return actorJson
}
