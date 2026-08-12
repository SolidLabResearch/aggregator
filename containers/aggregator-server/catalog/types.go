package catalog

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var ProfileGVR = schema.GroupVersionResource{Group: "aggregator.example.org", Version: "v1alpha1", Resource: "profiles"}
var DeploymentFunctionGVR = schema.GroupVersionResource{Group: "aggregator.example.org", Version: "v1alpha1", Resource: "deploymentfunctions"}

type Profile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ProfileSpec `json:"spec"`
}

type ProfileSpec struct {
	Prefixes        map[string]string         `json:"prefixes,omitempty"`
	ServiceProfile  *ServiceProfile           `json:"serviceProfile,omitempty"`
	DatasetProfiles map[string]DatasetProfile `json:"datasetProfiles,omitempty"`
}

type ServiceProfile struct {
	Title           string                `json:"title,omitempty"`
	Description     string                `json:"description,omitempty"`
	ExtraProperties map[string]string     `json:"extraProperties,omitempty"`
	AccessRoles     map[string]AccessRole `json:"accessRoles,omitempty"`
	Parameters      map[string]Parameter  `json:"parameters,omitempty"`
	Outputs         map[string]Output     `json:"outputs,omitempty"`
	Functions       map[string]Function   `json:"functions,omitempty"`
	Composition     []CompositionMapping  `json:"composition,omitempty"`
	Endpoints       map[string]Endpoint   `json:"endpoints,omitempty"`
}

type AccessRole struct {
	Title           string            `json:"title,omitempty"`
	Description     string            `json:"description,omitempty"`
	ExtraProperties map[string]string `json:"extraProperties,omitempty"`
}

type Parameter struct {
	Predicate       string            `json:"predicate"`
	Type            string            `json:"type"`
	Required        bool              `json:"required"`
	Title           string            `json:"title,omitempty"`
	Description     string            `json:"description,omitempty"`
	ExtraProperties map[string]string `json:"extraProperties,omitempty"`
}

type Output struct {
	Predicate       string            `json:"predicate"`
	Title           string            `json:"title,omitempty"`
	Description     string            `json:"description,omitempty"`
	DatasetProfile  DatasetReference  `json:"datasetProfileRef"`
	ExtraProperties map[string]string `json:"extraProperties,omitempty"`
}

type DatasetReference struct {
	Dataset string `json:"dataset"`
}

type Function struct {
	Name            string            `json:"name,omitempty"`
	Description     string            `json:"description,omitempty"`
	Expects         []string          `json:"expects"`
	Returns         []string          `json:"returns"`
	ExtraProperties map[string]string `json:"extraProperties,omitempty"`
}

type CompositionMapping struct {
	From CompositionSource `json:"from"`
	To   CompositionTarget `json:"to"`
}

type CompositionSource struct {
	Function string `json:"function"`
	Output   string `json:"output"`
}

type CompositionTarget struct {
	Function  string `json:"function"`
	Parameter string `json:"parameter"`
}

type Endpoint struct {
	Path            string            `json:"path"`
	Title           string            `json:"title,omitempty"`
	Description     string            `json:"description,omitempty"`
	Operations      []Operation       `json:"operations"`
	ExtraProperties map[string]string `json:"extraProperties,omitempty"`
}

type Operation struct {
	Method          string            `json:"method"`
	Executes        string            `json:"executes,omitempty"`
	Updates         *OperationUpdate  `json:"updates,omitempty"`
	Title           string            `json:"title,omitempty"`
	Description     string            `json:"description,omitempty"`
	AccessRoles     []string          `json:"accessRoles,omitempty"`
	ExtraProperties map[string]string `json:"extraProperties,omitempty"`
}

type OperationUpdate struct {
	Function   string   `json:"function"`
	Parameters []string `json:"parameters"`
}

type DatasetProfile struct {
	Title           string                         `json:"title,omitempty"`
	Description     string                         `json:"description,omitempty"`
	ExtraProperties map[string]string              `json:"extraProperties,omitempty"`
	Distributions   map[string]DistributionProfile `json:"distributions,omitempty"`
}

type DistributionProfile struct {
	Path            string            `json:"path"`
	URLType         string            `json:"urlType"`
	MediaType       string            `json:"mediaType,omitempty"`
	Format          string            `json:"format,omitempty"`
	Title           string            `json:"title,omitempty"`
	Description     string            `json:"description,omitempty"`
	AccessRoles     []string          `json:"accessRoles,omitempty"`
	ExtraProperties map[string]string `json:"extraProperties,omitempty"`
}

type DeploymentFunction struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              DeploymentFunctionSpec `json:"spec"`
}

type DeploymentFunctionSpec struct {
	Prefixes      map[string]string   `json:"prefixes,omitempty"`
	Function      DeploymentSignature `json:"function"`
	ProfileRef    *LocalReference     `json:"profileRef,omitempty"`
	Interface     *InlineInterface    `json:"interface,omitempty"`
	Orchestration Orchestration       `json:"orchestration"`
}

type DeploymentSignature struct {
	Title           string                `json:"title,omitempty"`
	Description     string                `json:"description,omitempty"`
	Expects         []DeploymentParameter `json:"expects"`
	Returns         DeploymentOutput      `json:"returns"`
	ExtraProperties map[string]string     `json:"extraProperties,omitempty"`
}

type DeploymentParameter struct {
	Name            string            `json:"name"`
	Predicate       string            `json:"predicate"`
	Type            string            `json:"type"`
	Required        bool              `json:"required"`
	Title           string            `json:"title,omitempty"`
	Description     string            `json:"description,omitempty"`
	ExtraProperties map[string]string `json:"extraProperties,omitempty"`
}

type DeploymentOutput struct {
	Name            string            `json:"name"`
	Predicate       string            `json:"predicate"`
	Title           string            `json:"title,omitempty"`
	Description     string            `json:"description,omitempty"`
	ExtraProperties map[string]string `json:"extraProperties,omitempty"`
}

type LocalReference struct {
	Name string `json:"name"`
}

type InlineInterface struct {
	Title           string                    `json:"title,omitempty"`
	Description     string                    `json:"description,omitempty"`
	ExtraProperties map[string]string         `json:"extraProperties,omitempty"`
	Endpoints       map[string]InlineEndpoint `json:"endpoints,omitempty"`
	Datasets        map[string]DatasetProfile `json:"datasets,omitempty"`
}

type InlineEndpoint struct {
	Path        string   `json:"path"`
	Methods     []string `json:"methods"`
	Title       string   `json:"title,omitempty"`
	Description string   `json:"description,omitempty"`
}

type Orchestration struct {
	Resources     []OrchestrationResource `json:"resources"`
	InputBindings []InputBinding          `json:"inputBindings,omitempty"`
	RouteBindings RouteBindings           `json:"routeBindings,omitempty"`
}

type OrchestrationResource struct {
	ID       string               `json:"id"`
	Manifest runtime.RawExtension `json:"manifest"`
}

type InputBinding struct {
	Parameter string               `json:"parameter"`
	Targets   []EnvironmentBinding `json:"targets"`
}

type EnvironmentBinding struct {
	Resource      string `json:"resource"`
	Container     string `json:"container"`
	Env           string `json:"env"`
	ValueTemplate string `json:"valueTemplate,omitempty"`
}

type RouteBindings struct {
	Endpoints     map[string]RouteTarget            `json:"endpoints,omitempty"`
	Distributions map[string]map[string]RouteTarget `json:"distributions,omitempty"`
}

type RouteTarget struct {
	Resource     string `json:"resource"`
	Container    string `json:"container"`
	Port         string `json:"port"`
	InternalPath string `json:"internalPath,omitempty"`
}

type Bundle struct {
	APIVersion         string             `json:"apiVersion"`
	Kind               string             `json:"kind"`
	DeploymentFunction DeploymentFunction `json:"deploymentFunction"`
	Profile            *Profile           `json:"profile,omitempty"`
}

const (
	BundleAPIVersion = "aggregator.example.org/v1alpha1"
	BundleKind       = "DeploymentBundle"
)

func NewBundle(definition DeploymentFunction, profile *Profile) Bundle {
	return Bundle{
		APIVersion:         BundleAPIVersion,
		Kind:               BundleKind,
		DeploymentFunction: definition,
		Profile:            profile,
	}
}
