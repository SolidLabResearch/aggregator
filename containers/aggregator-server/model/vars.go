package model

import (
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var Protocol string
var ExternalHost string

var AllowedRegistrationTypes []string
var ClientId string

// Standard OIDC Authorization Server configuration
var UMAServer string
var ClientSecret string

// Provision flow configuration
var ProvisionClientID string
var ProvisionClientSecret string
var ProvisionWebID string
var ProvisionAuthorizationServer string

// Kubernetes
var Namespace string
var Clientset kubernetes.Interface
var DynamicClient *dynamic.DynamicClient
var IngressClassName *string

var LogLevel logrus.Level
