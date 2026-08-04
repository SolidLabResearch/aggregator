package catalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"
)

type Registry struct {
	mu          sync.RWMutex
	urls        URLs
	profiles    map[string]Profile
	profileRDF  map[string][]byte
	deployments map[string]DeploymentFunction
	deployRDF   map[string][]byte
	bundles     map[string]cachedBundle
}

type cachedBundle struct {
	body []byte
	etag string
}

// Watch keeps the compiled registry current. It only reads CRDs and recompiles
// after Kubernetes reports a change; HTTP requests always use cached results.
func (r *Registry) Watch(ctx context.Context, client dynamic.Interface, namespace string, onError func(error)) {
	factory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(client, 0, namespace, nil)
	profiles := factory.ForResource(ProfileGVR).Informer()
	deployments := factory.ForResource(DeploymentFunctionGVR).Informer()
	changes := make(chan struct{}, 1)
	notify := func() {
		select {
		case changes <- struct{}{}:
		default:
		}
	}
	handler := cache.ResourceEventHandlerFuncs{
		AddFunc: func(any) { notify() }, UpdateFunc: func(any, any) { notify() }, DeleteFunc: func(any) { notify() },
	}
	_, _ = profiles.AddEventHandler(handler)
	_, _ = deployments.AddEventHandler(handler)
	factory.Start(ctx.Done())

	go func() {
		if !cache.WaitForCacheSync(ctx.Done(), profiles.HasSynced, deployments.HasSynced) {
			return
		}
		for {
			select {
			case <-ctx.Done():
				return
			case <-changes:
				timer := time.NewTimer(100 * time.Millisecond)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
				if err := r.Load(ctx, client, namespace); err != nil && onError != nil {
					onError(err)
				}
			}
		}
	}()
}

func NewRegistry(urls URLs) *Registry {
	return &Registry{
		urls: urls, profiles: map[string]Profile{}, profileRDF: map[string][]byte{},
		deployments: map[string]DeploymentFunction{}, deployRDF: map[string][]byte{}, bundles: map[string]cachedBundle{},
	}
}

func (r *Registry) Load(ctx context.Context, client dynamic.Interface, namespace string) error {
	profileList, err := client.Resource(ProfileGVR).Namespace(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list profiles: %w", err)
	}
	deploymentList, err := client.Resource(DeploymentFunctionGVR).Namespace(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list deployment functions: %w", err)
	}

	profiles := map[string]Profile{}
	profileRDF := map[string][]byte{}
	for _, item := range profileList.Items {
		var profile Profile
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(item.Object, &profile); err != nil {
			return fmt.Errorf("decode profile %q: %w", item.GetName(), err)
		}
		rdf, err := CompileProfile(&profile, r.urls)
		if err != nil {
			return fmt.Errorf("compile profile %q: %w", profile.Name, err)
		}
		profiles[profile.Name], profileRDF[profile.Name] = profile, rdf
	}

	deployments := map[string]DeploymentFunction{}
	deployRDF := map[string][]byte{}
	bundles := map[string]cachedBundle{}
	for _, item := range deploymentList.Items {
		var definition DeploymentFunction
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(item.Object, &definition); err != nil {
			return fmt.Errorf("decode deployment function %q: %w", item.GetName(), err)
		}
		var profile *Profile
		if definition.Spec.ProfileRef != nil {
			resolved, ok := profiles[definition.Spec.ProfileRef.Name]
			if !ok {
				return fmt.Errorf("deployment function %q references unknown profile %q", definition.Name, definition.Spec.ProfileRef.Name)
			}
			profile = &resolved
		}
		rdf, err := CompileDeploymentFunction(&definition, profile, r.urls)
		if err != nil {
			return fmt.Errorf("compile deployment function %q: %w", definition.Name, err)
		}
		bundle, err := cacheBundle(NewBundle(definition, profile))
		if err != nil {
			return fmt.Errorf("encode deployment function %q: %w", definition.Name, err)
		}
		deployments[definition.Name], deployRDF[definition.Name] = definition, rdf
		bundles[definition.Name] = bundle
	}

	r.mu.Lock()
	r.profiles, r.profileRDF, r.deployments, r.deployRDF, r.bundles = profiles, profileRDF, deployments, deployRDF, bundles
	r.mu.Unlock()
	return nil
}

func (r *Registry) ProfileRDF(name string) ([]byte, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	value, ok := r.profileRDF[name]
	return append([]byte(nil), value...), ok
}

func (r *Registry) DeploymentRDF(name string) ([]byte, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	value, ok := r.deployRDF[name]
	return append([]byte(nil), value...), ok
}

func (r *Registry) ProfileCatalog() []byte {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return CompileProfileCatalog(r.profileRDF, r.urls)
}

func (r *Registry) DeploymentCatalog() []byte {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return CompileDeploymentCatalog(r.deployRDF, r.urls)
}

func (r *Registry) Bundle(name string) (Bundle, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	definition, ok := r.deployments[name]
	if !ok {
		return Bundle{}, false
	}
	bundle := NewBundle(definition, nil)
	if definition.Spec.ProfileRef != nil {
		profile := r.profiles[definition.Spec.ProfileRef.Name]
		bundle.Profile = &profile
	}
	return bundle, true
}

func (r *Registry) BundleDocument(name string) ([]byte, string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	value, ok := r.bundles[name]
	return append([]byte(nil), value.body...), value.etag, ok
}

// Set installs already validated definitions. It is primarily useful for tests
// and is also the mutation boundary a Kubernetes watch will use.
func (r *Registry) Set(profiles []Profile, deployments []DeploymentFunction) error {
	profileMap, profileRDF := map[string]Profile{}, map[string][]byte{}
	for _, profile := range profiles {
		rdf, err := CompileProfile(&profile, r.urls)
		if err != nil {
			return err
		}
		profileMap[profile.Name], profileRDF[profile.Name] = profile, rdf
	}
	deploymentMap, deploymentRDF := map[string]DeploymentFunction{}, map[string][]byte{}
	bundles := map[string]cachedBundle{}
	for _, definition := range deployments {
		var profile *Profile
		if definition.Spec.ProfileRef != nil {
			value, ok := profileMap[definition.Spec.ProfileRef.Name]
			if !ok {
				return fmt.Errorf("profile %q was not resolved", definition.Spec.ProfileRef.Name)
			}
			profile = &value
		}
		rdf, err := CompileDeploymentFunction(&definition, profile, r.urls)
		if err != nil {
			return err
		}
		bundle, err := cacheBundle(NewBundle(definition, profile))
		if err != nil {
			return err
		}
		deploymentMap[definition.Name], deploymentRDF[definition.Name] = definition, rdf
		bundles[definition.Name] = bundle
	}
	r.mu.Lock()
	r.profiles, r.profileRDF, r.deployments, r.deployRDF, r.bundles = profileMap, profileRDF, deploymentMap, deploymentRDF, bundles
	r.mu.Unlock()
	return nil
}

func cacheBundle(bundle Bundle) (cachedBundle, error) {
	body, err := json.Marshal(bundle)
	if err != nil {
		return cachedBundle{}, err
	}
	hash := sha256.Sum256(body)
	return cachedBundle{body: append(body, '\n'), etag: `"` + hex.EncodeToString(hash[:8]) + `"`}, nil
}
