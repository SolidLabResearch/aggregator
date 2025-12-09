package httpclient

import (
	"context"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/semaphore"
	"net/http"
	"sync"
)

const MaxConcurrentRequestsPerHost = 30

type ThrottledClient struct {
	client     *http.Client
	semaphores map[string]*semaphore.Weighted
	mutex      sync.RWMutex
}

var DefaultClient *ThrottledClient

func init() {
	DefaultClient = NewThrottledClient(&http.Client{})
}

func NewThrottledClient(client *http.Client) *ThrottledClient {
	if client == nil {
		client = &http.Client{}
	}
	return &ThrottledClient{
		client:     client,
		semaphores: make(map[string]*semaphore.Weighted),
	}
}

func (tc *ThrottledClient) getSemaphore(host string) *semaphore.Weighted {
	tc.mutex.RLock()
	sem, exists := tc.semaphores[host]
	tc.mutex.RUnlock()

	if exists {
		return sem
	}

	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	sem, exists = tc.semaphores[host]
	if exists {
		return sem
	}

	sem = semaphore.NewWeighted(MaxConcurrentRequestsPerHost)
	tc.semaphores[host] = sem
	return sem
}

func (tc *ThrottledClient) Do(req *http.Request) (*http.Response, error) {
	host := req.URL.Host
	if host == "" {
		host = req.Host
	}

	sem := tc.getSemaphore(host)

	ctx := req.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	if err := sem.Acquire(ctx, 1); err != nil {
		return nil, err
	}
	defer sem.Release(1)

	logrus.WithFields(logrus.Fields{
		"host":   host,
		"method": req.Method,
		"url":    req.URL.String(),
	}).Debug("🚦 Throttled request executing")

	return tc.client.Do(req)
}

func (tc *ThrottledClient) Get(url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return tc.Do(req)
}
