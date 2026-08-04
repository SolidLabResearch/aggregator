package catalog

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type ValidationErrors []string

func (e ValidationErrors) Error() string { return strings.Join(e, "; ") }

func invalid(errors ValidationErrors) error {
	if len(errors) == 0 {
		return nil
	}
	sort.Strings(errors)
	return errors
}

func ValidateProfile(profile *Profile) error {
	var errors ValidationErrors
	if profile == nil {
		return ValidationErrors{"profile is nil"}
	}
	if profile.Name == "" {
		errors = append(errors, "metadata.name is required")
	}
	if profile.Spec.ServiceProfile == nil && len(profile.Spec.DatasetProfiles) == 0 {
		errors = append(errors, "serviceProfile or datasetProfiles is required")
	}
	service := profile.Spec.ServiceProfile
	if service == nil {
		return invalid(errors)
	}

	for name, output := range service.Outputs {
		if _, ok := profile.Spec.DatasetProfiles[output.DatasetProfile.Dataset]; !ok {
			errors = append(errors, fmt.Sprintf("output %q references unknown dataset profile %q", name, output.DatasetProfile.Dataset))
		}
	}
	for name, function := range service.Functions {
		for _, parameter := range function.Expects {
			if _, ok := service.Parameters[parameter]; !ok {
				errors = append(errors, fmt.Sprintf("function %q expects unknown parameter %q", name, parameter))
			}
		}
		for _, output := range function.Returns {
			if _, ok := service.Outputs[output]; !ok {
				errors = append(errors, fmt.Sprintf("function %q returns unknown output %q", name, output))
			}
		}
	}
	for index, mapping := range service.Composition {
		from, ok := service.Functions[mapping.From.Function]
		if !ok {
			errors = append(errors, fmt.Sprintf("composition[%d] references unknown source function %q", index, mapping.From.Function))
		} else if !includes(from.Returns, mapping.From.Output) {
			errors = append(errors, fmt.Sprintf("composition[%d] source function %q does not return %q", index, mapping.From.Function, mapping.From.Output))
		}
		to, ok := service.Functions[mapping.To.Function]
		if !ok {
			errors = append(errors, fmt.Sprintf("composition[%d] references unknown target function %q", index, mapping.To.Function))
		} else if !includes(to.Expects, mapping.To.Parameter) {
			errors = append(errors, fmt.Sprintf("composition[%d] target function %q does not expect %q", index, mapping.To.Function, mapping.To.Parameter))
		}
	}
	seen := map[string]string{}
	for name, endpoint := range service.Endpoints {
		for _, operation := range endpoint.Operations {
			key := strings.ToUpper(operation.Method) + " " + endpoint.Path
			if previous, ok := seen[key]; ok {
				errors = append(errors, fmt.Sprintf("endpoints %q and %q both define %s", previous, name, key))
			}
			seen[key] = name
			if operation.Executes != "" {
				if _, ok := service.Functions[operation.Executes]; !ok {
					errors = append(errors, fmt.Sprintf("endpoint %q executes unknown function %q", name, operation.Executes))
				}
			}
			if operation.Updates != nil {
				function, ok := service.Functions[operation.Updates.Function]
				if !ok {
					errors = append(errors, fmt.Sprintf("endpoint %q updates unknown function %q", name, operation.Updates.Function))
				} else {
					for _, parameter := range operation.Updates.Parameters {
						if !includes(function.Expects, parameter) {
							errors = append(errors, fmt.Sprintf("endpoint %q updates parameter %q not expected by function %q", name, parameter, operation.Updates.Function))
						}
					}
				}
			}
		}
	}
	return invalid(errors)
}

func ValidateBundle(bundle *Bundle) error {
	if bundle == nil {
		return ValidationErrors{"bundle is nil"}
	}
	var errors ValidationErrors
	definition := &bundle.DeploymentFunction
	if definition.Name == "" {
		errors = append(errors, "deploymentFunction.metadata.name is required")
	}
	if definition.Spec.Function.Returns.Name == "" {
		errors = append(errors, "function.returns.name is required")
	}
	if definition.Spec.Function.Returns.Predicate == "" {
		errors = append(errors, "function.returns.predicate is required")
	}
	if definition.Spec.ProfileRef != nil && definition.Spec.Interface != nil {
		errors = append(errors, "profileRef and interface are mutually exclusive")
	}
	if definition.Spec.ProfileRef != nil {
		if bundle.Profile == nil || bundle.Profile.Name != definition.Spec.ProfileRef.Name {
			errors = append(errors, fmt.Sprintf("profile %q was not resolved", definition.Spec.ProfileRef.Name))
		} else if err := ValidateProfile(bundle.Profile); err != nil {
			errors = append(errors, fmt.Sprintf("profile %q is invalid: %v", bundle.Profile.Name, err))
		}
	}

	parameters := map[string]DeploymentParameter{}
	for _, parameter := range definition.Spec.Function.Expects {
		if _, exists := parameters[parameter.Name]; exists {
			errors = append(errors, fmt.Sprintf("duplicate input name %q", parameter.Name))
		}
		parameters[parameter.Name] = parameter
	}

	resources := map[string]resourceInfo{}
	for _, resource := range definition.Spec.Orchestration.Resources {
		if _, exists := resources[resource.ID]; exists {
			errors = append(errors, fmt.Sprintf("duplicate resource id %q", resource.ID))
			continue
		}
		info, err := inspectResource(resource)
		if err != nil {
			errors = append(errors, fmt.Sprintf("resource %q: %v", resource.ID, err))
		}
		resources[resource.ID] = info
	}
	boundParameters := map[string]bool{}
	for _, binding := range definition.Spec.Orchestration.InputBindings {
		if _, ok := parameters[binding.Parameter]; !ok {
			errors = append(errors, fmt.Sprintf("input binding references unknown parameter %q", binding.Parameter))
		}
		if boundParameters[binding.Parameter] {
			errors = append(errors, fmt.Sprintf("duplicate input binding for parameter %q", binding.Parameter))
		}
		boundParameters[binding.Parameter] = true
		for _, target := range binding.Targets {
			validateContainer(&errors, resources, target.Resource, target.Container, "input binding")
		}
	}
	for name := range parameters {
		if !boundParameters[name] {
			errors = append(errors, fmt.Sprintf("missing input binding for parameter %q", name))
		}
	}
	validateRouteBindings(&errors, bundle, resources)
	return invalid(errors)
}

type resourceInfo struct {
	containers map[string]map[string]bool
}

func inspectResource(resource OrchestrationResource) (resourceInfo, error) {
	var manifest map[string]any
	if err := json.Unmarshal(resource.Manifest.Raw, &manifest); err != nil {
		return resourceInfo{}, fmt.Errorf("invalid manifest: %w", err)
	}
	kind, _ := manifest["kind"].(string)
	if kind != "Deployment" && kind != "PersistentVolumeClaim" && kind != "ConfigMap" {
		return resourceInfo{}, fmt.Errorf("unsupported kind %q", kind)
	}
	if metadata, ok := manifest["metadata"].(map[string]any); ok && (metadata["name"] != nil || metadata["namespace"] != nil) {
		return resourceInfo{}, fmt.Errorf("metadata.name and metadata.namespace are managed by the aggregator")
	}
	info := resourceInfo{containers: map[string]map[string]bool{}}
	if kind != "Deployment" {
		return info, nil
	}
	spec := objectAt(manifest, "spec", "template", "spec")
	containers, _ := spec["containers"].([]any)
	for _, item := range containers {
		container, _ := item.(map[string]any)
		name, _ := container["name"].(string)
		ports := map[string]bool{}
		portItems, _ := container["ports"].([]any)
		for _, portItem := range portItems {
			port, _ := portItem.(map[string]any)
			portName, _ := port["name"].(string)
			ports[portName] = true
		}
		info.containers[name] = ports
	}
	return info, nil
}

func validateRouteBindings(errors *ValidationErrors, bundle *Bundle, resources map[string]resourceInfo) {
	wantedEndpoints := map[string]bool{}
	wantedDistributions := map[string]map[string]bool{}
	if bundle.Profile != nil {
		if bundle.Profile.Spec.ServiceProfile != nil {
			for name := range bundle.Profile.Spec.ServiceProfile.Endpoints {
				wantedEndpoints[name] = true
			}
		}
		for datasetName, dataset := range bundle.Profile.Spec.DatasetProfiles {
			wantedDistributions[datasetName] = map[string]bool{}
			for name := range dataset.Distributions {
				wantedDistributions[datasetName][name] = true
			}
		}
	} else if bundle.DeploymentFunction.Spec.Interface != nil {
		for name := range bundle.DeploymentFunction.Spec.Interface.Endpoints {
			wantedEndpoints[name] = true
		}
		for datasetName, dataset := range bundle.DeploymentFunction.Spec.Interface.Datasets {
			wantedDistributions[datasetName] = map[string]bool{}
			for name := range dataset.Distributions {
				wantedDistributions[datasetName][name] = true
			}
		}
	}

	bindings := bundle.DeploymentFunction.Spec.Orchestration.RouteBindings
	for name := range wantedEndpoints {
		if _, ok := bindings.Endpoints[name]; !ok {
			*errors = append(*errors, fmt.Sprintf("missing route binding for endpoint %q", name))
		}
	}
	for name, target := range bindings.Endpoints {
		if !wantedEndpoints[name] {
			*errors = append(*errors, fmt.Sprintf("route binding references unknown endpoint %q", name))
		}
		validateRoute(errors, resources, target, "endpoint "+name)
	}
	for datasetName, distributions := range wantedDistributions {
		for distributionName := range distributions {
			if _, ok := bindings.Distributions[datasetName][distributionName]; !ok {
				*errors = append(*errors, fmt.Sprintf("missing route binding for dataset %q distribution %q", datasetName, distributionName))
			}
		}
	}
	for datasetName, distributions := range bindings.Distributions {
		for distributionName, target := range distributions {
			if !wantedDistributions[datasetName][distributionName] {
				*errors = append(*errors, fmt.Sprintf("route binding references unknown dataset %q distribution %q", datasetName, distributionName))
			}
			validateRoute(errors, resources, target, "dataset "+datasetName+" distribution "+distributionName)
		}
	}
}

func validateRoute(errors *ValidationErrors, resources map[string]resourceInfo, target RouteTarget, context string) {
	ports := validateContainer(errors, resources, target.Resource, target.Container, context)
	if !ports[target.Port] {
		*errors = append(*errors, fmt.Sprintf("%s references unknown port %q", context, target.Port))
	}
	if target.InternalPath != "" && !strings.HasPrefix(target.InternalPath, "/") {
		*errors = append(*errors, fmt.Sprintf("%s internalPath must begin with /", context))
	}
}

func validateContainer(errors *ValidationErrors, resources map[string]resourceInfo, resourceName, containerName, context string) map[string]bool {
	resource, ok := resources[resourceName]
	if !ok {
		*errors = append(*errors, fmt.Sprintf("%s references unknown resource %q", context, resourceName))
		return map[string]bool{}
	}
	ports, ok := resource.containers[containerName]
	if !ok {
		*errors = append(*errors, fmt.Sprintf("%s references unknown container %q", context, containerName))
		return map[string]bool{}
	}
	return ports
}

func objectAt(root map[string]any, path ...string) map[string]any {
	current := root
	for _, part := range path {
		current, _ = current[part].(map[string]any)
	}
	return current
}

func includes(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
