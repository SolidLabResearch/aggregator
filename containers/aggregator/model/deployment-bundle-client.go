package model

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

func FetchDeploymentBundle(ctx context.Context, name string) (*DeploymentBundle, error) {
	if AggregatorServerInternalURL == "" {
		return nil, fmt.Errorf("aggregator server internal URL is not configured")
	}
	requestURL := AggregatorServerInternalURL + "/internal/deployment-functions/" + url.PathEscape(name)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create deployment bundle request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	response, err := HttpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch deployment bundle %q: %w", name, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		return nil, fmt.Errorf("fetch deployment bundle %q: server returned %s: %s", name, response.Status, strings.TrimSpace(string(body)))
	}
	var bundle DeploymentBundle
	decoder := json.NewDecoder(io.LimitReader(response.Body, 10<<20))
	if err := decoder.Decode(&bundle); err != nil {
		return nil, fmt.Errorf("decode deployment bundle %q: %w", name, err)
	}
	if bundle.APIVersion != DeploymentBundleAPIVersion || bundle.Kind != DeploymentBundleKind {
		return nil, fmt.Errorf("unsupported deployment bundle envelope %q %q", bundle.APIVersion, bundle.Kind)
	}
	if bundle.DeploymentFunction.Name != name {
		return nil, fmt.Errorf("deployment bundle name %q does not match requested name %q", bundle.DeploymentFunction.Name, name)
	}
	return &bundle, nil
}

// ResolveDeploymentBundle converts the transport representation into the
// instance's native, immutable runtime definition.
func ResolveDeploymentBundle(uri string, bundle *DeploymentBundle) (*ResolvedDeployment, error) {
	if bundle == nil {
		return nil, fmt.Errorf("deployment bundle is nil")
	}
	definition := &bundle.DeploymentFunction

	prefixes := mergedBundlePrefixes(bundle)
	parameters := map[string]BundledDeploymentParameter{}
	for _, parameter := range definition.Spec.Function.Expects {
		parameters[parameter.Name] = parameter
	}

	resolved := &ResolvedDeployment{
		Name: definition.Name, URI: uri, Prefixes: prefixes,
		Datasets: map[string]ResolvedDataset{}, Endpoints: map[string]ResolvedEndpoint{},
	}
	for _, parameter := range definition.Spec.Function.Expects {
		resolved.Parameters = append(resolved.Parameters, ResolvedParameter{
			Name: parameter.Name, Predicate: expandBundleValue(parameter.Predicate, uri, prefixes),
			Type: expandBundleValue(parameter.Type, uri, prefixes), Required: parameter.Required,
		})
	}
	manifests := map[string]map[string]any{}
	for _, resource := range definition.Spec.Orchestration.Resources {
		var manifest map[string]any
		if err := json.Unmarshal(resource.Manifest.Raw, &manifest); err != nil {
			return nil, fmt.Errorf("decode resource %q: %w", resource.ID, err)
		}
		kind, _ := manifest["kind"].(string)
		if kind != "Deployment" && kind != "ConfigMap" && kind != "PersistentVolumeClaim" {
			return nil, fmt.Errorf("resource %q has unsupported kind %q", resource.ID, kind)
		}
		manifests[resource.ID] = manifest
		resolved.Resources = append(resolved.Resources, ResolvedResource{ID: resource.ID, Kind: kind, Manifest: resource.Manifest})
	}
	for _, binding := range definition.Spec.Orchestration.InputBindings {
		if _, ok := parameters[binding.Parameter]; !ok {
			return nil, fmt.Errorf("input binding references unknown parameter %q", binding.Parameter)
		}
		resolvedBinding := ResolvedInputBinding{
			Parameter: binding.Parameter,
			Predicate: expandBundleValue(parameters[binding.Parameter].Predicate, uri, prefixes),
		}
		for _, target := range binding.Targets {
			manifest, ok := manifests[target.Resource]
			if !ok {
				return nil, fmt.Errorf("input %q targets unknown resource %q", binding.Parameter, target.Resource)
			}
			if manifest["kind"] != "Deployment" {
				return nil, fmt.Errorf("input %q environment target resource %q is not a Deployment", binding.Parameter, target.Resource)
			}
			if _, err := findContainer(manifest, target.Container); err != nil {
				return nil, err
			}
			resolvedBinding.Targets = append(resolvedBinding.Targets, ResolvedEnvironmentTarget{
				Resource: target.Resource, Container: target.Container, Env: target.Env,
			})
		}
		resolved.InputBindings = append(resolved.InputBindings, resolvedBinding)
	}

	datasets, serviceProfile, profileURI, err := bundleInterface(bundle)
	if err != nil {
		return nil, err
	}
	resolved.ProfileURI = profileURI
	if serviceProfile != nil {
		resolved.ServiceProfile = &ResolvedServiceProfile{
			Title: serviceProfile.Title, Description: serviceProfile.Description,
			ExtraProperties: expandBundleMap(serviceProfile.ExtraProperties, uri, prefixes),
		}
	}
	for datasetName, datasetProfile := range datasets {
		dataset := ResolvedDataset{
			Title: datasetProfile.Title, Description: datasetProfile.Description,
			ExtraProperties: expandBundleMap(datasetProfile.ExtraProperties, uri, prefixes), Distributions: map[string]ResolvedDistribution{},
		}
		if profileURI != "" {
			dataset.ProfileURI = profileURI + "#dataset-" + datasetName
		}
		for distributionName, distributionProfile := range datasetProfile.Distributions {
			target, ok := definition.Spec.Orchestration.RouteBindings.Distributions[datasetName][distributionName]
			if !ok {
				return nil, fmt.Errorf("missing route for dataset %q distribution %q", datasetName, distributionName)
			}
			manifest, ok := manifests[target.Resource]
			if !ok {
				return nil, fmt.Errorf("distribution %q targets unknown resource %q", distributionName, target.Resource)
			}
			port, err := findContainerPort(manifest, target.Container, target.Port)
			if err != nil {
				return nil, err
			}
			dataset.Distributions[distributionName] = ResolvedDistribution{
				Title: distributionProfile.Title, Description: distributionProfile.Description,
				MediaType: distributionProfile.MediaType, Format: distributionProfile.Format,
				ExtraProperties: expandBundleMap(distributionProfile.ExtraProperties, uri, prefixes),
				Path:            distributionProfile.Path, URLType: distributionProfile.URLType,
				Target: ResolvedRouteTarget{Resource: target.Resource, Container: target.Container,
					PortName: target.Port, Port: port, InternalPath: target.InternalPath},
			}
		}
		resolved.Datasets[datasetName] = dataset
	}
	if bundle.Profile != nil && bundle.Profile.Spec.ServiceProfile != nil {
		for name, endpoint := range bundle.Profile.Spec.ServiceProfile.Endpoints {
			resolvedEndpoint, err := resolveEndpointTarget(name, endpoint.Path, definition.Spec.Orchestration.RouteBindings.Endpoints[name], manifests)
			if err != nil {
				return nil, err
			}
			for _, operation := range endpoint.Operations {
				value := ResolvedOperation{Method: operation.Method, Executes: operation.Executes}
				if operation.Updates != nil {
					value.UpdatesFunction = operation.Updates.Function
					value.UpdatesParameters = append([]string(nil), operation.Updates.Parameters...)
				}
				resolvedEndpoint.Operations = append(resolvedEndpoint.Operations, value)
			}
			resolved.Endpoints[name] = resolvedEndpoint
		}
	} else if definition.Spec.Interface != nil {
		for name, endpoint := range definition.Spec.Interface.Endpoints {
			resolvedEndpoint, err := resolveEndpointTarget(name, endpoint.Path, definition.Spec.Orchestration.RouteBindings.Endpoints[name], manifests)
			if err != nil {
				return nil, err
			}
			for _, method := range endpoint.Methods {
				resolvedEndpoint.Operations = append(resolvedEndpoint.Operations, ResolvedOperation{Method: method})
			}
			resolved.Endpoints[name] = resolvedEndpoint
		}
	}
	return resolved, nil
}

func bundleInterface(bundle *DeploymentBundle) (map[string]BundledDatasetProfile, *BundledServiceProfile, string, error) {
	definition := bundle.DeploymentFunction.Spec
	if definition.ProfileRef != nil {
		if bundle.Profile == nil || bundle.Profile.Name != definition.ProfileRef.Name {
			return nil, nil, "", fmt.Errorf("profile %q was not resolved in bundle", definition.ProfileRef.Name)
		}
		return bundle.Profile.Spec.DatasetProfiles, bundle.Profile.Spec.ServiceProfile,
			ExternalServerURL() + "/profiles/" + bundle.Profile.Name, nil
	}
	if definition.Interface == nil {
		return map[string]BundledDatasetProfile{}, nil, "", nil
	}
	service := &BundledServiceProfile{Title: definition.Interface.Title, Description: definition.Interface.Description, ExtraProperties: definition.Interface.ExtraProperties}
	return definition.Interface.Datasets, service, "", nil
}

func resolveEndpointTarget(name, path string, target BundledRouteTarget, manifests map[string]map[string]any) (ResolvedEndpoint, error) {
	manifest, ok := manifests[target.Resource]
	if !ok {
		return ResolvedEndpoint{}, fmt.Errorf("endpoint %q targets unknown resource %q", name, target.Resource)
	}
	port, err := findContainerPort(manifest, target.Container, target.Port)
	if err != nil {
		return ResolvedEndpoint{}, fmt.Errorf("endpoint %q: %w", name, err)
	}
	return ResolvedEndpoint{Path: path, Target: ResolvedRouteTarget{
		Resource: target.Resource, Container: target.Container, PortName: target.Port,
		Port: port, InternalPath: target.InternalPath,
	}}, nil
}

func mergedBundlePrefixes(bundle *DeploymentBundle) map[string]string {
	result := map[string]string{
		"aggr": "https://w3id.org/aggregator#", "dcat": "http://www.w3.org/ns/dcat#",
		"dct": "http://purl.org/dc/terms/", "fno": "https://w3id.org/function/ontology#",
		"xsd": "http://www.w3.org/2001/XMLSchema#",
	}
	if bundle.Profile != nil {
		for key, value := range bundle.Profile.Spec.Prefixes {
			result[key] = value
		}
	}
	for key, value := range bundle.DeploymentFunction.Spec.Prefixes {
		result[key] = value
	}
	return result
}

func expandBundleValue(value, document string, prefixes map[string]string) string {
	if strings.Contains(value, "://") {
		return value
	}
	if prefix, local, ok := strings.Cut(value, ":"); ok {
		if base, exists := prefixes[prefix]; exists {
			return base + local
		}
	}
	return document + "#" + value
}

func expandBundleMap(values map[string]string, document string, prefixes map[string]string) map[string]string {
	result := map[string]string{}
	for predicate, value := range values {
		result[expandBundleValue(predicate, document, prefixes)] = expandBundleObject(value, prefixes)
	}
	return result
}

func expandBundleObject(value string, prefixes map[string]string) string {
	if strings.Contains(value, "://") {
		return value
	}
	if prefix, local, ok := strings.Cut(value, ":"); ok {
		if base, exists := prefixes[prefix]; exists {
			return base + local
		}
	}
	return value
}

func findContainerPort(manifest map[string]any, containerName, portName string) (int, error) {
	container, err := findContainer(manifest, containerName)
	if err != nil {
		return 0, err
	}
	ports, _ := container["ports"].([]any)
	for _, item := range ports {
		port, _ := item.(map[string]any)
		if port["name"] == portName {
			if number, ok := port["containerPort"].(float64); ok && number > 0 {
				return int(number), nil
			}
		}
	}
	return 0, fmt.Errorf("container %q has no named port %q", containerName, portName)
}

func findContainer(manifest map[string]any, containerName string) (map[string]any, error) {
	containers, err := deploymentContainers(manifest)
	if err != nil {
		return nil, err
	}
	for _, item := range containers {
		container, _ := item.(map[string]any)
		if container["name"] == containerName {
			return container, nil
		}
	}
	return nil, fmt.Errorf("unknown container %q", containerName)
}

func deploymentContainers(manifest map[string]any) ([]any, error) {
	spec, ok := manifest["spec"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("Deployment has no spec")
	}
	template, ok := spec["template"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("Deployment has no pod template")
	}
	podSpec, ok := template["spec"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("Deployment has no pod spec")
	}
	containers, ok := podSpec["containers"].([]any)
	if !ok {
		return nil, fmt.Errorf("Deployment has no containers")
	}
	return containers, nil
}
