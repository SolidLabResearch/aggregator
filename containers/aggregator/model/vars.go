package model

import (
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

// Network configuration
var Protocol string
var ExternalHost string
var ExternalHttpPort string
var ExternalHttpsPort string

func ExternalURL() string {
	if Protocol == "https" {
		if ExternalHttpsPort == "443" {
			return "https://" + ExternalHost + "/" + ID
		}
		return "https://" + ExternalHost + ":" + ExternalHttpsPort + "/" + ID
	}
	if ExternalHttpPort == "80" {
		return "http://" + ExternalHost + "/" + ID
	}
	return "http://" + ExternalHost + ":" + ExternalHttpPort + "/" + ID
}

// Aggregator identity
var Owner User
var ID string
var ProvisionID string
var Namespace string

// Aggregator configuration
var ServiceCollection string
var TransformationCatalog string

var ClientId string

var Clientset kubernetes.Interface
var DynamicClient *dynamic.DynamicClient

var LogLevel logrus.Level

// localhost safe http client with pooling
var HttpClient = &http.Client{
	Transport: &rewriteLocalhostTransport{
		base: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
	},
}
