package model

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/maartyman/rdfgo"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Service struct {
	NamespaceID      string
	InstanceID       string
	Path             string
	Exe              Execution
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
		err := Clientset.AppsV1().Deployments(Namespace).Delete(ctx, dep.Name, metav1.DeleteOptions{})
		if err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete deployment %s: %w", dep.Name, err)
		}
	}

	// Delete Services
	for _, svc := range service.Services {
		err := Clientset.CoreV1().Services(Namespace).Delete(ctx, svc.Name, metav1.DeleteOptions{})
		if err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("failed to delete service %s: %w", svc.Name, err)
		}
	}

	return nil
}

func (service *Service) Status() string {
	ctx := context.Background()
	for _, dep := range service.Deployments {
		d, err := Clientset.AppsV1().Deployments(Namespace).Get(ctx, dep.Name, metav1.GetOptions{})
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
	svcNode := rdfgo.NewNamedNode(service.Exe.URI)

	go func() {
		defer close(stream)

		// service URI is a service and execution
		quad, err := rdfgo.NewQuad(
			svcNode,
			rdfgo.IRI.RDF.Type,
			Agg("Service"),
			nil,
		)
		if err != nil {
			return
		}
		stream <- quad
		quad, err = rdfgo.NewQuad(
			svcNode,
			rdfgo.IRI.RDF.Type,
			FnO("Execution"),
			nil,
		)
		if err != nil {
			return
		}
		stream <- quad

		// SERVICE DETAILS
		// service status
		quad, err = rdfgo.NewQuad(
			svcNode,
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
			svcNode,
			Agg("createdAt"),
			rdfgo.NewLiteral(service.CreatedAt.Format(time.RFC3339), "", DateTime),
			nil,
		)
		if err != nil {
			return
		}
		stream <- quad

		// EXECUTION DETAILS
		// transformation
		quad, err = rdfgo.NewQuad(
			svcNode,
			FnO("executes"),
			rdfgo.NewNamedNode(service.Exe.Transformation.URI),
			nil,
		)
		if err != nil {
			return
		}
		stream <- quad

		// parameters
		for param, value := range service.Exe.Params {
			quad, err = rdfgo.NewQuad(
				svcNode,
				rdfgo.NewNamedNode(param),
				value,
				nil,
			)
			if err != nil {
				return
			}
			stream <- quad
		}

		// outputs
		for output, value := range service.Exe.Outputs {
			quad, err = rdfgo.NewQuad(
				svcNode,
				rdfgo.NewNamedNode(output),
				value,
				nil,
			)
			if err != nil {
				return
			}
			stream <- quad
		}
	}()

	// serialize to turtle
	var buf bytes.Buffer
	_, err := rdfgo.Write(stream.ToIStream(), &buf, rdfgo.WriterOptions{Format: "turtle"})
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
