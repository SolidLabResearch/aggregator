package model

import (
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var Protocol string
var ExternalHost string

var DisableAuth bool
var AllowedRegistrationTypes []string
var ClientId string

// Standard OIDC Authorization Server configuration
var AuthServer string
var ClientSecret string

// Provision flow configuration
var ProvisionClientID string
var ProvisionClientSecret string
var ProvisionWebID string
var ProvisionAuthorizationServer string

// Kubernetes clients
var Clientset kubernetes.Interface
var DynamicClient *dynamic.DynamicClient

var LogLevel logrus.Level
