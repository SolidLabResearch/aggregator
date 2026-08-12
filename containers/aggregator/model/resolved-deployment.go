package model

import "k8s.io/apimachinery/pkg/runtime"

type ResolvedDeployment struct {
	Name           string
	URI            string
	ProfileURI     string
	Prefixes       map[string]string
	ServiceProfile *ResolvedServiceProfile
	Parameters     []ResolvedParameter
	Resources      []ResolvedResource
	InputBindings  []ResolvedInputBinding
	Datasets       map[string]ResolvedDataset
	Endpoints      map[string]ResolvedEndpoint
}

type ResolvedParameter struct {
	Name      string
	Predicate string
	Type      string
	Required  bool
}

type ResolvedEndpoint struct {
	Path       string
	Operations []ResolvedOperation
	Target     ResolvedRouteTarget
}

type ResolvedOperation struct {
	Method            string
	Executes          string
	UpdatesFunction   string
	UpdatesParameters []string
	Scopes            []Scope
	AccessRoles       []string
}

type ResolvedServiceProfile struct {
	Title           string
	Description     string
	ExtraProperties map[string]string
	AccessRoles     map[string]ResolvedAccessRole
}

type ResolvedAccessRole struct {
	URI             string
	Title           string
	Description     string
	ExtraProperties map[string]string
}

type ResolvedResource struct {
	ID       string
	Kind     string
	Manifest runtime.RawExtension
}

type ResolvedInputBinding struct {
	Parameter string
	Predicate string
	Targets   []ResolvedEnvironmentTarget
}

type ResolvedEnvironmentTarget struct {
	Resource      string
	Container     string
	Env           string
	ValueTemplate string
}

type ResolvedDataset struct {
	Title           string
	Description     string
	ExtraProperties map[string]string
	ProfileURI      string
	Distributions   map[string]ResolvedDistribution
}

type ResolvedDistribution struct {
	Title           string
	Description     string
	ExtraProperties map[string]string
	MediaType       string
	Format          string
	Path            string
	URLType         string
	AccessRoles     []string
	Target          ResolvedRouteTarget
}

type ResolvedRouteTarget struct {
	Resource     string
	Container    string
	PortName     string
	Port         int
	InternalPath string
}
