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
	"strings"
	"time"
)

var serverMux *http.ServeMux

func InitializeKubernetes(mux *http.ServeMux) {
	serverMux = mux
}

type Actor struct {
	Id                  string `json:"id"`
	PipelineDescription string `json:"pipelineDescription"`
	pod                 *v1.Pod
}

// TODO This needs to be more generic and extensible
func createActor(pipelineDescription string) (Actor, error) {
	id := uuid.New().String()

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
					Name:            "transformation",
					Image:           "incremunica",
					ImagePullPolicy: v1.PullNever,
					Env: []v1.EnvVar{
						{Name: "PIPELINE_DESCRIPTION", Value: fmt.Sprintf("%v", pipelineDescription)},
						{Name: "HTTP_PROXY", Value: "http://uma-proxy-service.default.svc.cluster.local:8080"},
						{Name: "HTTPS_PROXY", Value: "http://uma-proxy-service.default.svc.cluster.local:8443"},
						{Name: "SSL_CERT_FILE", Value: "/key-pair/uma-proxy.crt"},
					},
					Ports: []v1.ContainerPort{
						{ContainerPort: 8080},
					},
					VolumeMounts: []v1.VolumeMount{
						{
							Name:      "key-pair",
							MountPath: "/key-pair",
							ReadOnly:  true,
						},
					},
				},
			},
			Volumes: []v1.Volume{
				{
					Name: "key-pair",
					VolumeSource: v1.VolumeSource{
						Secret: &v1.SecretVolumeSource{
							SecretName: "uma-proxy-key-pair",
						},
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

	var handleAllRequests = func(w http.ResponseWriter, r *http.Request) {
		log.Println("Received request for actor:", id, "Path:", r.URL.Path, "Method:", r.Method)
		if !auth.AuthorizeRequest(w, r, nil) {
			return
		}

		// Extract the subpath after the actor ID
		actorPrefix := "/" + id + "/"
		subPath := strings.TrimPrefix(r.URL.Path, actorPrefix)

		// Construct the target URL with the subpath and query parameters
		targetURL := fmt.Sprintf("http://%s:%d/%s", nodeIp, nodePort, subPath)
		if r.URL.RawQuery != "" {
			targetURL += "?" + r.URL.RawQuery
		}

		// Create a new request with the same method, headers, and body
		req, err := http.NewRequest(r.Method, targetURL, r.Body)
		if err != nil {
			fmt.Println("Error creating request:", err.Error())
			http.Error(w, "Failed to create request", http.StatusInternalServerError)
			return
		}

		// Copy headers from original request
		for name, values := range r.Header {
			for _, value := range values {
				req.Header.Add(name, value)
			}
		}

		// Make the request to the pod
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("Error reaching pod service:", err.Error())
			http.Error(w, "Failed to reach pod service", http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		// Copy response headers
		for name, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}

		// Set status code
		w.WriteHeader(resp.StatusCode)

		// Check if this is a streaming response (like SSE)
		contentType := resp.Header.Get("Content-Type")
		isSSE := strings.Contains(contentType, "text/event-stream")

		log.Println("Content-Type:", contentType, "IsSSE:", isSSE)
		if isSSE {
			// Handle Server-Sent Events streaming
			flusher, ok := w.(http.Flusher)
			if !ok {
				http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
				return
			}

			// Stream the response in chunks
			buffer := make([]byte, 1024)
			for {
				n, err := resp.Body.Read(buffer)
				if n > 0 {
					w.Write(buffer[:n])
					flusher.Flush() // Immediately send data to client
				}
				if err != nil {
					if err != io.EOF {
						fmt.Printf("Error reading SSE stream: %v\n", err)
					}
					break
				}
			}
		} else {
			// Handle regular responses
			io.Copy(w, resp.Body)
		}
	}

	serverMux.HandleFunc("/"+id+"/", handleAllRequests)

	// Also handle exact match without trailing slash for backwards compatibility
	serverMux.HandleFunc("/"+id, handleAllRequests)

	actor := Actor{
		Id:                  id,
		PipelineDescription: pipelineDescription,
		pod:                 pod,
	}

	return actor, nil
}

func (actor Actor) Stop() {
	if actor.pod != nil {
		// TODO stop service as well
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := Clientset.CoreV1().Pods("default").Delete(ctx, actor.pod.Name, metav1.DeleteOptions{})
		if err != nil {
			fmt.Println("Error stopping actor:", err.Error())
		} else {
			fmt.Println("Actor stopped successfully:", actor.Id)
		}
	}
}

// TODO: should return the status of the actor (running, stopped, errors, ect.)
func (actor Actor) marshalActor() string {
	pipelineForJson := strings.ReplaceAll(actor.PipelineDescription, `"`, `\"`)
	pipelineForJson = strings.ReplaceAll(pipelineForJson, "\n", `\n`)
	actorJson := fmt.Sprintf(
		`{"id":"%s","transformation":"%s"}`,
		actor.Id,
		pipelineForJson,
	)
	return actorJson
}
