package model

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/url"
	"sort"
	"time"

	"github.com/maartyman/rdfgo"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Execution struct {
	URI            string
	Transformation string
	Params         map[string]rdfgo.ITerm
}

type Transformation struct {
	ID            string
	Image         string
	InputMapping  map[string]string
	OutputMapping map[string]OutputMapping
}

type OutputMapping struct {
	Port int32
	Path string
}

func (tf *Transformation) Ports() []int32 {
	unique := make(map[int32]struct{})

	for _, out := range tf.OutputMapping {
		unique[out.Port] = struct{}{}
	}

	ports := make([]int32, 0, len(unique))
	for p := range unique {
		ports = append(ports, p)
	}

	sort.Slice(ports, func(i, j int) bool {
		return ports[i] < ports[j]
	})

	return ports
}

type Service struct {
	ID               string
	Path             string
	Exe              Execution
	Namespace        string
	Endpoints        []string
	ClusterEndpoints []string
	Deployments      []appsv1.Deployment
	Services         []corev1.Service
	Ingresses        []networkingv1.Ingress
	CreatedAt        time.Time
}

func (service *Service) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Delete Deployments
	for _, dep := range service.Deployments {
		err := Clientset.AppsV1().Deployments(service.Namespace).Delete(ctx, dep.Name, metav1.DeleteOptions{})
		if err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete deployment %s: %w", dep.Name, err)
		}
	}

	// Delete Services
	for _, svc := range service.Services {
		err := Clientset.CoreV1().Services(service.Namespace).Delete(ctx, svc.Name, metav1.DeleteOptions{})
		if err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete service %s: %w", svc.Name, err)
		}
	}

	// Delete Ingresses
	for _, ing := range service.Ingresses {
		err := Clientset.NetworkingV1().Ingresses(service.Namespace).Delete(ctx, ing.Name, metav1.DeleteOptions{})
		if err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete ingress %s: %w", ing.Name, err)
		}
	}

	return nil
}

func (service *Service) Status() string {
	ctx := context.Background()
	for _, dep := range service.Deployments {
		d, err := Clientset.AppsV1().Deployments(service.Namespace).Get(ctx, dep.Name, metav1.GetOptions{})
		if err != nil {
			return "errored"
		}
		if d.Status.AvailableReplicas == 0 {
			return "starting" // or stopped/starting
		}
	}

	// Check if the service endpoint is actually responding
	if len(service.ClusterEndpoints) > 0 {
		endpoint := service.ClusterEndpoints[0]

		// Parse the URL to extract host and port
		u, err := url.Parse(endpoint)
		if err != nil {
			return "starting"
		}

		// Try to establish a TCP connection
		conn, err := net.DialTimeout("tcp", u.Host, 200*time.Millisecond)
		if err != nil {
			return "starting"
		}
		defer conn.Close()
	}

	return "running"
}

func (service *Service) FnORepresentation() ([]byte, error) {
	stream := rdfgo.NewStream()

	go func() {
		defer close(stream)

		// service URI is a service
		quad, err := rdfgo.NewQuad(
			rdfgo.NewNamedNode(service.Exe.URI),
			rdfgo.IRI.RDF.Type,
			FnO("Service"),
			nil,
		)
		if err != nil {
			return
		}
		stream <- quad

		// service status
		quad, err = rdfgo.NewQuad(
			rdfgo.NewNamedNode(service.Exe.URI),
			Agg("status"),
			rdfgo.NewStringLiteral(service.Status(), "en"),
			nil,
		)
		if err != nil {
			return
		}
		stream <- quad

		// service createdAt
		quad, err = rdfgo.NewQuad(
			rdfgo.NewNamedNode(service.Exe.URI),
			Agg("createdAt"),
			rdfgo.NewLiteral(service.CreatedAt.Format(time.RFC3339), "", DateTime),
			nil,
		)
		if err != nil {
			return
		}
		stream <- quad

		// used transformation
		tfNode := rdfgo.NewBlankNode("tf")

		quad, err = rdfgo.NewQuad(
			tfNode,
			rdfgo.IRI.RDF.Type,
			FnO("Execution"),
			nil,
		)
		if err != nil {
			return
		}
		stream <- quad

		quad, err = rdfgo.NewQuad(
			tfNode,
			FnO("executes"),
			rdfgo.NewNamedNode(service.Exe.Transformation),
			nil,
		)
		if err != nil {
			return
		}
		stream <- quad

		for param, value := range service.Exe.Params {
			quad, err = rdfgo.NewQuad(
				tfNode,
				rdfgo.NewNamedNode(param),
				value,
				nil,
			)
			if err != nil {
				return
			}
			stream <- quad
		}

		quad, err = rdfgo.NewQuad(
			rdfgo.NewNamedNode(service.Exe.URI),
			Agg("transformation"),
			tfNode,
			nil,
		)
		if err != nil {
			return
		}
		stream <- quad
	}()

	// serialize to turtle
	var buf bytes.Buffer
	_, err := rdfgo.Write(stream.ToIStream(), &buf, rdfgo.WriterOptions{Format: "turtle"})
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
