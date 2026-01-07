package model

import (
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var Protocol string
var ExternalHost string

var ClientId string
var ClientSecret string

var Clientset *kubernetes.Clientset
var DynamicClient *dynamic.DynamicClient

var LogLevel logrus.Level
