package instance

import (
	"aggregator/model"
	"context"
	"encoding/json"
	"fmt"

	"github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func ensureEgress(
	aggregatorId string,
	tokenEndpoint string,
	accessToken string,
	refreshToken string,
	accessTokenExpiry string,
	ctx context.Context,
) error {
	tokensPayload, err := buildTokensPayload(accessToken, refreshToken, accessTokenExpiry)
	if err != nil {
		return fmt.Errorf("failed to build egress-uma token payload: %w", err)
	}

	cmName, err := ensureConfigMap(aggregatorId, "egress-uma-config", tokensPayload, ctx)
	if err != nil {
		return fmt.Errorf("failed to ensure egress-uma configmap: %w", err)
	}

	if err := ensureEgressDeployment(aggregatorId, 1, tokenEndpoint, cmName, ctx); err != nil {
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

func ensureEgressDeployment(aggregatorId string, replicas int32, tokenEndpoint string, configName string, ctx context.Context) error {
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
							Image:           "egress-uma",
							ImagePullPolicy: corev1.PullNever,
							Ports: []corev1.ContainerPort{
								{ContainerPort: 8080},
							},
							Env: []corev1.EnvVar{
								{Name: "CLIENT_ID", Value: model.ClientId},
								{Name: "CLIENT_SECRET", Value: model.ClientSecret},
								{Name: "TOKEN_ENDPOINT", Value: tokenEndpoint},
								{Name: "UPDATE_TOKENS_FILE", Value: "/etc/config/tokens.json"},
								{Name: "LOG_LEVEL", Value: model.LogLevel.String()},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      configName,
									MountPath: "/etc/config",
									ReadOnly:  true,
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: configName,
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: configName,
									},
								},
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
