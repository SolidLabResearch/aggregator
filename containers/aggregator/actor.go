package main

import (
	"aggregator/auth"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	namespace := "aggregator-ns"

	// ----------------------------
	// 1. Pod spec
	// ----------------------------
	image := os.Getenv("TRANSFORMATION")
	if image == "" {
		return Actor{}, fmt.Errorf("TRANSFORMATION env var is not set")
	}

	podSpec := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: id,
			Labels: map[string]string{
				"app": id,
			},
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:            "transformation",
					Image:           image,
					ImagePullPolicy: v1.PullNever,
					Env: []v1.EnvVar{
						{Name: "PIPELINE_DESCRIPTION", Value: pipelineDescription},
						{Name: "SSL_CERT_FILE", Value: "/key-pair/uma-proxy.crt"},
						{Name: "HTTP_PROXY", Value: "http://uma-proxy.uma-proxy-ns.svc.cluster.local:8080"},
						{Name: "HTTPS_PROXY", Value: "http://uma-proxy.uma-proxy-ns.svc.cluster.local:8443"},
						{Name: "http_proxy", Value: "http://uma-proxy.uma-proxy-ns.svc.cluster.local:8080"},
						{Name: "https_proxy", Value: "http://uma-proxy.uma-proxy-ns.svc.cluster.local:8443"},
						{Name: "LOG_LEVEL", Value: LogLevel.String()},
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

	// ----------------------------
	// 2. Create Pod
	// ----------------------------
	pod, err := Clientset.CoreV1().Pods(namespace).Create(ctx, podSpec, metav1.CreateOptions{})
	if err != nil {
		return Actor{}, fmt.Errorf("failed to create pod in namespace %s: %w", namespace, err)
	}

	// ----------------------------
	// 3. Service spec
	// ----------------------------
	serviceName := "id-" + id + "-service"
	serviceSpec := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: serviceName,
		},
		Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeClusterIP,
			Selector: map[string]string{
				"app": id,
			},
			Ports: []v1.ServicePort{
				{
					Port:       80,
					TargetPort: intstr.FromInt(8080),
				},
			},
		},
	}

	_, err = Clientset.CoreV1().Services(namespace).Create(ctx, serviceSpec, metav1.CreateOptions{})
	if err != nil {
		return Actor{}, fmt.Errorf("failed to create service in namespace %s: %w", namespace, err)
	}

	// ----------------------------
	// 4. Wait for Pod Running
	// ----------------------------
	watcher, err := Clientset.CoreV1().Pods(namespace).Watch(ctx, metav1.ListOptions{
		FieldSelector: fmt.Sprintf("metadata.name=%s", id),
	})
	if err != nil {
		return Actor{}, err
	}
	defer watcher.Stop()

podLoop:
	for event := range watcher.ResultChan() {
		p, ok := event.Object.(*v1.Pod)
		if !ok {
			continue
		}
		switch p.Status.Phase {
		case v1.PodRunning:
			break podLoop
		case v1.PodFailed:
			return Actor{}, fmt.Errorf("pod failed: %v", p.Status.Reason)
		}
	}

	// -----------------------------
	// 5. Register handler in aggregator
	// -----------------------------
	var requestHandler = func(w http.ResponseWriter, r *http.Request) {
		logrus.WithFields(logrus.Fields{"actor_id": id, "path": r.URL.Path, "method": r.Method}).Info("Received request for actor")
		if !auth.AuthorizeRequest(w, r, nil) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Extract the subpath after the actor ID
		actorPrefix := "/" + id + "/"
		subPath := strings.TrimPrefix(r.URL.Path, actorPrefix)

		// Construct the target URL with the subpath and query parameters
		serviceURL := fmt.Sprintf("http://%s.%s.svc.cluster.local:80/%s", serviceName, namespace, subPath)
		if r.URL.RawQuery != "" {
			serviceURL += "?" + r.URL.RawQuery
		}

		req, err := http.NewRequest(r.Method, serviceURL, r.Body)
		if err != nil {
			http.Error(w, "failed to create request", http.StatusInternalServerError)
			return
		}
		req.Header = r.Header.Clone()

		// Make the request to the service
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			fmt.Println("Failed to reach actor service:", err.Error())
			http.Error(w, "failed to reach actor service", http.StatusBadGateway)
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
		logrus.WithFields(logrus.Fields{"content_type": contentType, "is_sse": isSSE}).Debug("Content-Type response")

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
						logrus.WithFields(logrus.Fields{"err": err}).Error("Error reading SSE stream")
					}
					break
				}
			}
		} else {
			// Handle regular responses
			io.Copy(w, resp.Body)
		}
	}

	serverMux.HandleFunc("/"+id+"/", requestHandler)
	serverMux.HandleFunc("/"+id, requestHandler)

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
			logrus.WithFields(logrus.Fields{"err": err, "actor_id": actor.Id}).Error("Error stopping actor")
		} else {
			logrus.WithFields(logrus.Fields{"actor_id": actor.Id}).Info("Actor stopped successfully")
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
