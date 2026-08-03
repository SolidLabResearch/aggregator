package model

import (
	"net/http"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var Protocol string
var TLSSecret string
var ExternalHost string
var ExternalHttpPort string
var ExternalHttpsPort string

func ExternalURL() string {
	if TLSSecret != "" {
		if ExternalHttpsPort == "443" {
			return "https://" + ExternalHost
		}
		return "https://" + ExternalHost + ":" + ExternalHttpsPort
	}

	if ExternalHttpPort == "80" {
		return "http://" + ExternalHost
	}
	return "http://" + ExternalHost + ":" + ExternalHttpPort
}

var AllowedRegistrationTypes []string

// Standard OIDC Authentication configuration
var OIDCClientId string
var OIDCClientSecret string
var OIDCServer string

// Solid OIDC Authentication configuration
var SolidClientId string

// Provision flow configuration
var ProvisionClientID string
var ProvisionClientSecret string
var ProvisionWebID string
var ProvisionIDP string
var ProvisionAuthorizationServer string
var IDPServerType string

// Client credentials
var ClientCredId string
var ClientCredSecret string

// Kubernetes
var Namespace string
var Clientset kubernetes.Interface
var DynamicClient *dynamic.DynamicClient
var IngressClassName *string

// Spec configuration
var DeploymentCatalog string
var ServiceCollection string
var RegistrationEndpoint string

// Http client that handles localhost
var HttpClient = &http.Client{
	Transport: &localRedirectTransport{
		rt: http.DefaultTransport,
	},
	Timeout: 0,
}

var LogLevel logrus.Level
var DisableAuth bool
