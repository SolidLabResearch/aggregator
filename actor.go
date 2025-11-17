package main

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
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
			RestartPolicy: v1.RestartPolicyOnFailure,
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
					Port:       80,                     // The port your client will use
					TargetPort: intstr.FromInt32(8080), // The port inside the pod
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
		logrus.WithFields(logrus.Fields{"err": err}).Error("Failed to list nodes")
		return Actor{}, err
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

	logrus.WithFields(logrus.Fields{"url": fmt.Sprintf("http://%s:%d", nodeIp, nodePort)}).Info("Pod is running")

	serverMux.HandleFunc("/"+id+"/", AuthProxyInstance.HandleAllRequests)

	serverMux.HandleFunc("/"+id, AuthProxyInstance.HandleAllRequests)

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
