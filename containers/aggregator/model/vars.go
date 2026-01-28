package model

import (
	"net/http"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

// Network configuration
var Protocol string
var ExternalHost string
var ProxyClient *http.Client

// Aggregator identity
var Owner User
var ID string
var Namespace string

// Aggregator configuration
var BaseUrl string
var ServiceCollection string
var TransformationCatalog string

var ClientId string

var Clientset kubernetes.Interface
var DynamicClient *dynamic.DynamicClient

var LogLevel logrus.Level
