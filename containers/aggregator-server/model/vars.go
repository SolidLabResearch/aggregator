package model

import (
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var Protocol string
var ExternalHost string

// Standard OIDC Authorization Server configuration
var AuthServer string
var ClientId string
var AggregatorSecret string

var DisableAuth bool
var AllowedRegistrationTypes []string

// Provisioning credentials for "provision" registration type
var ProvisionClientID string
var ProvisionClientSecret string
var ProvisionWebID string
var ProvisionAuthorizationServer string

var Clientset *kubernetes.Clientset
var DynamicClient *dynamic.DynamicClient

var LogLevel logrus.Level
