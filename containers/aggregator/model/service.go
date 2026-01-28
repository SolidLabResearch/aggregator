package model

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/maartyman/rdfgo"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Service struct {
	NamespaceID string
	InstanceID  string
	Path        string
	Exe         Execution
	CreatedAt   time.Time
}

func (service *Service) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Label selector to match the resources
	labelSelector := fmt.Sprintf(
		"app.kubernetes.io/name=aggregator-service,agg.knows.idlab.ugent.be/managed-by=%s,agg.knows.idlab.ugent.be/id=%s",
		ID,
		service.InstanceID,
	)
	// Ensure dependent resources are deleted
	deletePolicy := metav1.DeletePropagationForeground

	// Delete Deployments
	if err := Clientset.AppsV1().Deployments(Namespace).DeleteCollection(ctx, metav1.DeleteOptions{
		PropagationPolicy: &deletePolicy,
	}, metav1.ListOptions{
		LabelSelector: labelSelector,
	}); err != nil {
		return fmt.Errorf("failed to delete deployments: %w", err)
	}

	// Delete Services
	services, err := Clientset.CoreV1().Services(Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return fmt.Errorf("failed to list services: %w", err)
	}

	for _, svc := range services.Items {
		if err := Clientset.CoreV1().Services(Namespace).Delete(ctx, svc.Name, metav1.DeleteOptions{
			PropagationPolicy: &deletePolicy,
		}); err != nil {
			return fmt.Errorf("failed to delete service %s: %w", svc.Name, err)
		}
	}

	return nil
}

func (service *Service) Status() string {
	ctx := context.Background()

	// Label selector to match the resources
	labelSelector := fmt.Sprintf(
		"app.kubernetes.io/name=aggregator-service,agg.knows.idlab.ugent.be/managed-by=%s,agg.knows.idlab.ugent.be/id=%s",
		ID,
		service.InstanceID,
	)

	// Check services and their endpoints
	services, err := Clientset.CoreV1().Services(Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return "errored"
	}
	if len(services.Items) == 0 {
		return "stopped"
	}

	for _, svc := range services.Items {
		endpoints, err := Clientset.CoreV1().Endpoints(Namespace).Get(ctx, svc.Name, metav1.GetOptions{})
		if err != nil {
			return "errored"
		}

		// Check if the service has any ready endpoints
		hasReady := false
		for _, subset := range endpoints.Subsets {
			if len(subset.Addresses) > 0 {
				hasReady = true
				break
			}
		}
		if !hasReady {
			return "starting" // service exists but no pods are ready
		}
	}

	// All deployments have available replicas & services have endpoints
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
