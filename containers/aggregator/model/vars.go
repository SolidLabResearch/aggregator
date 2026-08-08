package model

import (
	"net/http"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
)

// Network configuration
var ExternalHost string
var ExternalProto string
var ExternalPort string

func ExternalBaseURL() string {
	return ExternalServerURL() + "/" + ID
}

func ExternalServerURL() string {
	if ExternalProto == "https" {
		if ExternalPort == "" || ExternalPort == "443" {
			return "https://" + ExternalHost
		}
		return "https://" + ExternalHost + ":" + ExternalPort
	}
	if ExternalPort == "" || ExternalPort == "80" {
		return "http://" + ExternalHost
	}
	return "http://" + ExternalHost + ":" + ExternalPort
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
