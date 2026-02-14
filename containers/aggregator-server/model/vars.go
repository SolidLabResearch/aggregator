package model

import (
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var Protocol string
var TLSSecret string
var ExternalHost string

var AllowedRegistrationTypes []string
var ClientId string

// Standard OIDC Authorization Server configuration
var AuthServer string
var ClientSecret string

// Provision flow configuration
var ProvisionClientID string
var ProvisionClientSecret string
var ProvisionWebID string
var ProvisionIDP string
var ProvisionAuthorizationServer string
var IDPServerType string

// Kubernetes
var Namespace string
var Clientset kubernetes.Interface
var DynamicClient *dynamic.DynamicClient
var IngressClassName *string

// Spec configuration
var TransformationCatalog string
var ServiceCollection string
var RegistrationEndpoint string

// Http client that handles localhost
var HttpClient = &http.Client{
	Transport: &localRedirectTransport{
		rt: http.DefaultTransport,
	},
	Timeout: 5 * time.Second,
}

var LogLevel logrus.Level
