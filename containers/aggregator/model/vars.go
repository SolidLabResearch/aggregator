package model

import (
	"net/http"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
)

// Network configuration
var Protocol string
var ExternalHost string
var ExternalHttpPort string
var ExternalHttpsPort string

func ExternalBaseURL() string {
	return ExternalServerURL() + "/" + ID
}

func ExternalServerURL() string {
	if Protocol == "https" {
		if ExternalHttpsPort == "" || ExternalHttpsPort == "443" {
			return "https://" + ExternalHost
		}
		return "https://" + ExternalHost + ":" + ExternalHttpsPort
	}
	if ExternalHttpPort == "" || ExternalHttpPort == "80" {
		return "http://" + ExternalHost
	}
	return "http://" + ExternalHost + ":" + ExternalHttpPort
}

// Aggregator identity
var Owner User
var ID string
var ProvisionID string
var Namespace string

// Aggregator configuration
var ServiceCollection string
var DeploymentCatalog string
var AggregatorServerInternalURL string

var Clientset kubernetes.Interface
var LogLevel logrus.Level

// localhost safe http client with pooling
var HttpClient = &http.Client{
	Transport: &rewriteLocalhostTransport{
		base: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     0,
		},
	},
	Timeout: 0,
}
