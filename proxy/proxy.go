package proxy

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
)

type ProxyConfig struct {
	LogLevel string
}

func isPodRunning(clientset *kubernetes.Clientset) (bool, error) {
	pods, err := clientset.CoreV1().Pods("default").List(context.Background(), metav1.ListOptions{
		LabelSelector: fmt.Sprintf("app=%s", "uma-proxy"),
	})
	if err != nil {
		return false, err
	}

	for _, pod := range pods.Items {
		if pod.Status.Phase == v1.PodRunning {
			return true, nil
		}
	}

	return false, nil
}

func createPod(clientset *kubernetes.Clientset, config ProxyConfig) error {
	envVars := []v1.EnvVar{
		{
			Name:  "CERT_PATH",
			Value: "/key-pair/uma-proxy.crt",
		},
		{
			Name:  "KEY_PATH",
			Value: "/key-pair/uma-proxy.key",
		},
		{
			Name:  "LOG_LEVEL",
			Value: config.LogLevel,
		},
	}

	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "uma-proxy",
			Labels: map[string]string{
				"app": "uma-proxy",
			},
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:            "uma-proxy",
					Image:           "uma-proxy",
					ImagePullPolicy: v1.PullNever,
					Ports: []v1.ContainerPort{
						{ContainerPort: 8080},
						{ContainerPort: 8443},
					},
					VolumeMounts: []v1.VolumeMount{
						{
							Name:      "key-pair",
							MountPath: "/key-pair",
							ReadOnly:  true,
						},
					},
					Env: envVars,
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
		},
	}
	_, err := clientset.CoreV1().Pods("default").Create(context.Background(), pod, metav1.CreateOptions{})
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("Failed to create uma-proxy pod")
		return err
	}
	return nil
}

func serviceExists(clientset *kubernetes.Clientset) (bool, error) {
	_, err := clientset.CoreV1().Services("default").Get(context.Background(), "uma-proxy-service", metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func createService(clientset *kubernetes.Clientset) error {
	svc := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: "uma-proxy-service",
		},
		Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeClusterIP, // internal access
			Selector: map[string]string{
				"app": "uma-proxy", // must match pod label
			},
			Ports: []v1.ServicePort{
				{
					Name:       "http",
					Port:       8080,
					TargetPort: intstr.FromInt(8080),
				},
				{
					Name:       "https",
					Port:       8443,
					TargetPort: intstr.FromInt(8443),
				},
			},
		},
	}
	_, err := clientset.CoreV1().Services("default").Create(context.Background(), svc, metav1.CreateOptions{})
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("Failed to create uma-proxy service")
		return err
	}
	return nil
}

func SetupProxy(clientset *kubernetes.Clientset, config ProxyConfig) {
	if running, err := isPodRunning(clientset); err != nil || !running {
		err := createPod(clientset, config)
		if err != nil {
			panic(err)
		}

		watcher, _ := clientset.CoreV1().Pods("default").Watch(context.Background(), metav1.ListOptions{
			FieldSelector: fmt.Sprintf("metadata.name=%s", "uma-proxy"),
		})

		for event := range watcher.ResultChan() {
			pod := event.Object.(*v1.Pod)
			if pod.Status.Phase == v1.PodRunning {
				break
			} else if pod.Status.Phase == v1.PodFailed {
				panic("proxy pod failed to start")
			}
		}
	}
	if exists, err := serviceExists(clientset); err != nil || !exists {
		err := createService(clientset)
		if err != nil {
			panic(err)
		}
	}
}
