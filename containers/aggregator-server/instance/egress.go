package instance

import (
	"aggregator/model"
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

var EgressUmaImage = os.Getenv("EGRESS-UMA_IMAGE") + ":" + os.Getenv("EGRESS-UMA_TAG")
var EgressUmaPullPolicy = os.Getenv("EGRESS-UMA_PULL_POLICY")

func ensureEgress(
	aggregatorId string,
	ownerID string,
	ctx context.Context,
) error {
	if err := ensureEgressDeployment(aggregatorId, 1, ownerID, ctx); err != nil {
		return fmt.Errorf("failed to ensure egress-uma deployment: %w", err)
	}

	if err := ensureEgressService(aggregatorId, ctx); err != nil {
		return fmt.Errorf("failed to ensure egress-uma service: %w", err)
	}

	logrus.Infof("Egress deployed for %s", aggregatorId)
	return nil
}

func buildTokensPayload(accessToken string, refreshToken string, accessTokenExpiry string) (map[string]string, error) {
	payload := map[string]string{
		"access_token":        accessToken,
		"refresh_token":       refreshToken,
		"access_token_expiry": accessTokenExpiry,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return map[string]string{"tokens.json": string(data)}, nil
}

func ensureEgressDeployment(aggregatorId string, replicas int32, ownerID string, ctx context.Context) error {
	egressName := "egress-uma-" + aggregatorId
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      egressName,
			Namespace: model.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":              "aggregator-instance",
				"app.kubernetes.io/components":        "egress-uma",
				"app.kubernetes.io/part-of":           "aggregator-platform",
				"app.kubernetes.io/managed-by":        "aggregator-instance",
				"agg.knows.idlab.ugent.be/managed-by": aggregatorId,
				"agg.knows.idlab.ugent.be/id":         egressName,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app.kubernetes.io/name":              "aggregator-instance",
					"app.kubernetes.io/components":        "egress-uma",
					"agg.knows.idlab.ugent.be/managed-by": aggregatorId,
					"agg.knows.idlab.ugent.be/id":         egressName,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app.kubernetes.io/name":              "aggregator-instance",
						"app.kubernetes.io/components":        "egress-uma",
						"app.kubernetes.io/part-of":           "aggregator-platform",
						"app.kubernetes.io/managed-by":        "aggregator-instance",
						"agg.knows.idlab.ugent.be/managed-by": aggregatorId,
						"agg.knows.idlab.ugent.be/id":         egressName,
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: "egress-uma-sa",
					Containers: []corev1.Container{
						{
							Name:            "egress-uma",
							Image:           EgressUmaImage,
							ImagePullPolicy: corev1.PullPolicy(EgressUmaPullPolicy),
							Ports: []corev1.ContainerPort{
								{ContainerPort: 8080},
							},
							Env: []corev1.EnvVar{
								{Name: "USER_ID", Value: ownerID},
								{Name: "AGGREGATOR_ID", Value: aggregatorId},
								{Name: "OIDC_SERVER", Value: model.OIDCServer},
								{Name: "LOG_LEVEL", Value: model.LogLevel.String()},
							},
						},
					},
				},
			},
		},
	}

	_, err := model.Clientset.AppsV1().Deployments(model.Namespace).Create(ctx, deployment, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	logrus.Infof("Egress UMA deployment created for %s ✅", aggregatorId)
	return nil
}

func ensureEgressService(aggregatorId string, ctx context.Context) error {
	egressName := "egress-uma-" + aggregatorId
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      egressName,
			Namespace: model.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":              "aggregator-instance",
				"app.kubernetes.io/components":        "egress-uma",
				"app.kubernetes.io/part-of":           "aggregator-platform",
				"app.kubernetes.io/managed-by":        "aggregator-instance",
				"agg.knows.idlab.ugent.be/managed-by": aggregatorId,
				"agg.knows.idlab.ugent.be/id":         egressName,
			},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app.kubernetes.io/name":              "aggregator-instance",
				"app.kubernetes.io/components":        "egress-uma",
				"app.kubernetes.io/managed-by":        "aggregator-instance",
				"agg.knows.idlab.ugent.be/managed-by": aggregatorId,
				"agg.knows.idlab.ugent.be/id":         egressName,
			},
			Ports: []corev1.ServicePort{
				{
					Protocol:   corev1.ProtocolTCP,
					Port:       8080,
					TargetPort: intstr.FromInt(8080),
				},
			},
		},
	}

	_, err := model.Clientset.CoreV1().Services(model.Namespace).Create(ctx, service, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	logrus.Infof("Egress UMA service created for %s ✅", aggregatorId)
	return nil
}
