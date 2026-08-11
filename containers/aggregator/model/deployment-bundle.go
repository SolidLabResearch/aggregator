package model

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	DeploymentBundleAPIVersion = "aggregator.example.org/v1alpha1"
	DeploymentBundleKind       = "DeploymentBundle"
)

type DeploymentBundle struct {
	APIVersion         string                    `json:"apiVersion"`
	Kind               string                    `json:"kind"`
	DeploymentFunction BundledDeploymentFunction `json:"deploymentFunction"`
	Profile            *BundledProfile           `json:"profile,omitempty"`
}

type BundledDeploymentFunction struct {
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              BundledDeploymentFunctionSpec `json:"spec"`
}

type BundledDeploymentFunctionSpec struct {
	Prefixes      map[string]string          `json:"prefixes,omitempty"`
	Function      BundledDeploymentSignature `json:"function"`
	ProfileRef    *BundledLocalReference     `json:"profileRef,omitempty"`
	Interface     *BundledInlineInterface    `json:"interface,omitempty"`
	Orchestration BundledOrchestration       `json:"orchestration"`
}

type BundledDeploymentSignature struct {
	Title       string                       `json:"title,omitempty"`
	Description string                       `json:"description,omitempty"`
	Expects     []BundledDeploymentParameter `json:"expects"`
	Returns     BundledDeploymentOutput      `json:"returns"`
}

type BundledDeploymentParameter struct {
	Name      string `json:"name"`
	Predicate string `json:"predicate"`
	Type      string `json:"type"`
	Required  bool   `json:"required"`
}

type BundledDeploymentOutput struct {
	Name      string `json:"name"`
	Predicate string `json:"predicate"`
}

type BundledLocalReference struct {
	Name string `json:"name"`
}

type BundledOrchestration struct {
	Resources     []BundledResource     `json:"resources"`
	InputBindings []BundledInputBinding `json:"inputBindings,omitempty"`
	RouteBindings BundledRouteBindings  `json:"routeBindings,omitempty"`
}

type BundledResource struct {
	ID       string               `json:"id"`
	Manifest runtime.RawExtension `json:"manifest"`
}

type BundledInputBinding struct {
	Parameter string                      `json:"parameter"`
	Targets   []BundledEnvironmentBinding `json:"targets"`
}

type BundledEnvironmentBinding struct {
	Resource      string `json:"resource"`
	Container     string `json:"container"`
	Env           string `json:"env"`
	ValueTemplate string `json:"valueTemplate,omitempty"`
}

type BundledRouteBindings struct {
	Endpoints     map[string]BundledRouteTarget            `json:"endpoints,omitempty"`
	Distributions map[string]map[string]BundledRouteTarget `json:"distributions,omitempty"`
}

type BundledRouteTarget struct {
	Resource     string `json:"resource"`
	Container    string `json:"container"`
	Port         string `json:"port"`
	InternalPath string `json:"internalPath,omitempty"`
}

type BundledProfile struct {
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              BundledProfileSpec `json:"spec"`
}

type BundledProfileSpec struct {
	Prefixes        map[string]string                `json:"prefixes,omitempty"`
	ServiceProfile  *BundledServiceProfile           `json:"serviceProfile,omitempty"`
	DatasetProfiles map[string]BundledDatasetProfile `json:"datasetProfiles,omitempty"`
}

type BundledServiceProfile struct {
	Title           string                     `json:"title,omitempty"`
	Description     string                     `json:"description,omitempty"`
	ExtraProperties map[string]string          `json:"extraProperties,omitempty"`
	Endpoints       map[string]BundledEndpoint `json:"endpoints,omitempty"`
}

type BundledEndpoint struct {
	Path       string             `json:"path"`
	Operations []BundledOperation `json:"operations"`
}

type BundledOperation struct {
	Method   string                  `json:"method"`
	Executes string                  `json:"executes,omitempty"`
	Updates  *BundledOperationUpdate `json:"updates,omitempty"`
}

type BundledOperationUpdate struct {
	Function   string   `json:"function"`
	Parameters []string `json:"parameters"`
}

type BundledInlineInterface struct {
	Title           string                           `json:"title,omitempty"`
	Description     string                           `json:"description,omitempty"`
	ExtraProperties map[string]string                `json:"extraProperties,omitempty"`
	Endpoints       map[string]BundledInlineEndpoint `json:"endpoints,omitempty"`
	Datasets        map[string]BundledDatasetProfile `json:"datasets,omitempty"`
}

type BundledInlineEndpoint struct {
	Path    string   `json:"path"`
	Methods []string `json:"methods"`
}

type BundledDatasetProfile struct {
	Title           string                                `json:"title,omitempty"`
	Description     string                                `json:"description,omitempty"`
	ExtraProperties map[string]string                     `json:"extraProperties,omitempty"`
	Distributions   map[string]BundledDistributionProfile `json:"distributions,omitempty"`
}

type BundledDistributionProfile struct {
	Path            string            `json:"path"`
	URLType         string            `json:"urlType"`
	MediaType       string            `json:"mediaType,omitempty"`
	Format          string            `json:"format,omitempty"`
	Title           string            `json:"title,omitempty"`
	Description     string            `json:"description,omitempty"`
	ExtraProperties map[string]string `json:"extraProperties,omitempty"`
}
