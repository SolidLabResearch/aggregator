package catalog

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const (
	aggr = "https://w3id.org/aggregator#"
	dcat = "http://www.w3.org/ns/dcat#"
	dct  = "http://purl.org/dc/terms/"
	fno  = "https://w3id.org/function/ontology#"
)

type URLs struct{ Server string }

func (u URLs) profiles() string    { return strings.TrimRight(u.Server, "/") + "/profiles" }
func (u URLs) deployments() string { return strings.TrimRight(u.Server, "/") + "/deployments" }
func (u URLs) Profile(name string) string {
	return u.profiles() + "/" + name
}
func (u URLs) Deployment(name string) string {
	return u.deployments() + "/" + name
}

func CompileProfile(profile *Profile, urls URLs) ([]byte, error) {
	if err := ValidateProfile(profile); err != nil {
		return nil, err
	}
	document := urls.Profile(profile.Name)
	var out strings.Builder
	writePrefixes(&out)

	if service := profile.Spec.ServiceProfile; service != nil {
		startResource(&out, document, aggr+"ServiceProfile")
		writeOptionalLiteral(&out, dct+"title", service.Title)
		writeOptionalLiteral(&out, dct+"description", service.Description)
		writeExtraProperties(&out, document, service.ExtraProperties, profile.Spec.Prefixes)
		writeIRIs(&out, aggr+"accessRole", keyedIRIs(document, "role", service.AccessRoles))
		writeIRIs(&out, aggr+"performs", keyedIRIs(document, "function", service.Functions))
		writeIRIs(&out, aggr+"supportsEndpoint", keyedIRIs(document, "endpoint", service.Endpoints))
		if len(service.Composition) > 0 {
			writeSubject(&out, "", aggr+"composition", iri(document+"#composition"), true)
		} else {
			finishSubject(&out)
		}

		for _, name := range sortedKeys(service.AccessRoles) {
			role := service.AccessRoles[name]
			startResource(&out, fragment(document, "role", name), aggr+"AccessRole")
			writeOptionalLiteral(&out, dct+"title", role.Title)
			writeOptionalLiteral(&out, dct+"description", role.Description)
			writeExtraProperties(&out, document, role.ExtraProperties, profile.Spec.Prefixes)
			finishSubject(&out)
		}
		for _, name := range sortedKeys(service.Parameters) {
			parameter := service.Parameters[name]
			startResource(&out, fragment(document, "parameter", name), fno+"Parameter")
			writeOptionalLiteral(&out, fno+"name", parameter.Title)
			writeOptionalLiteral(&out, dct+"description", parameter.Description)
			writeExtraProperties(&out, document, parameter.ExtraProperties, profile.Spec.Prefixes)
			writeSubject(&out, "", fno+"predicate", iri(predicateURI(document, parameter.Predicate, profile.Spec.Prefixes)), true)
			writeSubject(&out, "", fno+"type", iri(expand(parameter.Type, profile.Spec.Prefixes)), true)
			writeSubject(&out, "", fno+"required", strconv.FormatBool(parameter.Required), true)
			finishSubject(&out)
		}
		for _, name := range sortedKeys(service.Outputs) {
			output := service.Outputs[name]
			startResource(&out, fragment(document, "output", name), fno+"Output")
			writeOptionalLiteral(&out, fno+"name", output.Title)
			writeOptionalLiteral(&out, dct+"description", output.Description)
			writeExtraProperties(&out, document, output.ExtraProperties, profile.Spec.Prefixes)
			writeSubject(&out, "", fno+"predicate", iri(predicateURI(document, output.Predicate, profile.Spec.Prefixes)), true)
			writeSubject(&out, "", dct+"conformsTo", iri(fragment(document, "dataset", output.DatasetProfile.Dataset)), true)
			finishSubject(&out)
		}
		for _, name := range sortedKeys(service.Functions) {
			function := service.Functions[name]
			startResource(&out, fragment(document, "function", name), fno+"Function")
			writeOptionalLiteral(&out, fno+"name", function.Name)
			writeOptionalLiteral(&out, dct+"description", function.Description)
			writeExtraProperties(&out, document, function.ExtraProperties, profile.Spec.Prefixes)
			writeList(&out, fno+"expects", refs(document, "parameter", function.Expects))
			writeList(&out, fno+"returns", refs(document, "output", function.Returns))
			finishSubject(&out)
		}
		compileComposition(&out, document, service.Composition)
		compileEndpoints(&out, document, service.Endpoints, profile.Spec.Prefixes)
	}

	for _, datasetName := range sortedKeys(profile.Spec.DatasetProfiles) {
		dataset := profile.Spec.DatasetProfiles[datasetName]
		startResource(&out, fragment(document, "dataset", datasetName), aggr+"DatasetProfile")
		writeOptionalLiteral(&out, dct+"title", dataset.Title)
		writeOptionalLiteral(&out, dct+"description", dataset.Description)
		writeExtraProperties(&out, document, dataset.ExtraProperties, profile.Spec.Prefixes)
		distributionIRIs := make([]string, 0, len(dataset.Distributions))
		for _, distributionName := range sortedKeys(dataset.Distributions) {
			distributionIRIs = append(distributionIRIs, fragment(document, "distribution", datasetName+"-"+distributionName))
		}
		writeIRIs(&out, aggr+"distributionProfile", distributionIRIs)
		finishSubject(&out)

		for _, distributionName := range sortedKeys(dataset.Distributions) {
			distribution := dataset.Distributions[distributionName]
			startResource(&out, fragment(document, "distribution", datasetName+"-"+distributionName), aggr+"DistributionProfile")
			writeOptionalLiteral(&out, dct+"title", distribution.Title)
			writeOptionalLiteral(&out, dct+"description", distribution.Description)
			writeExtraProperties(&out, document, distribution.ExtraProperties, profile.Spec.Prefixes)
			writeSubject(&out, "", aggr+"path", literal(distribution.Path), true)
			writeSubject(&out, "", aggr+"urlProperty", iri(dcat+distribution.URLType), true)
			writeIRIs(&out, aggr+"accessRole", roleIRIs(document, distribution.AccessRoles))
			if distribution.MediaType != "" {
				writeSubject(&out, "", dcat+"mediaType", iri("https://www.iana.org/assignments/media-types/"+distribution.MediaType), true)
			}
			if distribution.Format != "" {
				writeSubject(&out, "", dct+"format", rdfValue(distribution.Format, profile.Spec.Prefixes), true)
			}
			finishSubject(&out)
		}
	}
	return []byte(out.String()), nil
}

func CompileDeploymentFunction(definition *DeploymentFunction, profile *Profile, urls URLs) ([]byte, error) {
	bundle := NewBundle(*definition, profile)
	if err := ValidateBundle(&bundle); err != nil {
		return nil, err
	}
	document := urls.Deployment(definition.Name)
	var out strings.Builder
	writePrefixes(&out)
	startResource(&out, document, fno+"Function")
	writeOptionalLiteral(&out, fno+"name", definition.Spec.Function.Title)
	writeOptionalLiteral(&out, dct+"description", definition.Spec.Function.Description)
	writeExtraProperties(&out, document, definition.Spec.Function.ExtraProperties, definition.Spec.Prefixes)
	parameterIRIs := make([]string, 0, len(definition.Spec.Function.Expects))
	for _, parameter := range definition.Spec.Function.Expects {
		parameterIRIs = append(parameterIRIs, fragment(document, "parameter", parameter.Name))
	}
	writeList(&out, fno+"expects", parameterIRIs)
	writeList(&out, fno+"returns", []string{fragment(document, "output", definition.Spec.Function.Returns.Name)})
	finishSubject(&out)

	for _, parameter := range definition.Spec.Function.Expects {
		startResource(&out, fragment(document, "parameter", parameter.Name), fno+"Parameter")
		writeOptionalLiteral(&out, fno+"name", parameter.Title)
		writeOptionalLiteral(&out, dct+"description", parameter.Description)
		writeExtraProperties(&out, document, parameter.ExtraProperties, definition.Spec.Prefixes)
		writeSubject(&out, "", fno+"predicate", iri(predicateURI(document, parameter.Predicate, definition.Spec.Prefixes)), true)
		writeSubject(&out, "", fno+"type", iri(expand(parameter.Type, definition.Spec.Prefixes)), true)
		writeSubject(&out, "", fno+"required", strconv.FormatBool(parameter.Required), true)
		finishSubject(&out)
	}
	output := definition.Spec.Function.Returns
	startResource(&out, fragment(document, "output", output.Name), fno+"Output")
	writeOptionalLiteral(&out, fno+"name", output.Title)
	writeOptionalLiteral(&out, dct+"description", output.Description)
	writeExtraProperties(&out, document, output.ExtraProperties, definition.Spec.Prefixes)
	writeSubject(&out, "", fno+"predicate", iri(predicateURI(document, output.Predicate, definition.Spec.Prefixes)), true)
	writeSubject(&out, "", fno+"type", iri(aggr+"Service"), true)
	if definition.Spec.ProfileRef != nil {
		writeSubject(&out, "", dct+"conformsTo", iri(urls.Profile(definition.Spec.ProfileRef.Name)), true)
	}
	finishSubject(&out)
	return []byte(out.String()), nil
}

func CompileProfileCatalog(profiles map[string][]byte, urls URLs) []byte {
	var out strings.Builder
	writePrefixes(&out)
	startResource(&out, urls.profiles(), aggr+"ProfileCatalog")
	writeSubject(&out, "", dct+"title", literal("Aggregator profiles"), true)
	names := sortedKeys(profiles)
	profileIRIs := make([]string, 0, len(names))
	for _, name := range names {
		profileIRIs = append(profileIRIs, urls.Profile(name))
	}
	writeIRIs(&out, aggr+"hasProfile", profileIRIs)
	finishSubject(&out)
	return []byte(out.String())
}

func CompileDeploymentCatalog(deployments map[string][]byte, urls URLs) []byte {
	var out strings.Builder
	writePrefixes(&out)
	startResource(&out, urls.deployments(), aggr+"DeploymentCatalog")
	writeSubject(&out, "", dct+"title", literal("Aggregator deployment functions"), true)
	names := sortedKeys(deployments)
	functionIRIs := make([]string, 0, len(names))
	for _, name := range names {
		functionIRIs = append(functionIRIs, urls.Deployment(name))
	}
	writeIRIs(&out, aggr+"hasDeploymentFunction", functionIRIs)
	finishSubject(&out)
	return []byte(out.String())
}

func compileComposition(out *strings.Builder, document string, mappings []CompositionMapping) {
	if len(mappings) == 0 {
		return
	}
	startResource(out, document+"#composition", "https://fno.io/vocabulary/composition/0.1.0/Composition")
	items := make([]string, 0, len(mappings))
	for index := range mappings {
		items = append(items, fmt.Sprintf("%s#composition-mapping-%d", document, index))
	}
	writeIRIs(out, "https://fno.io/vocabulary/composition/0.1.0/composedOf", items)
	finishSubject(out)
	for index, mapping := range mappings {
		mappingIRI := fmt.Sprintf("%s#composition-mapping-%d", document, index)
		startResource(out, mappingIRI, "https://fno.io/vocabulary/composition/0.1.0/Mapping")
		writeSubject(out, "", "https://fno.io/vocabulary/composition/0.1.0/mapFrom", iri(mappingIRI+"-from"), true)
		writeSubject(out, "", "https://fno.io/vocabulary/composition/0.1.0/mapTo", iri(mappingIRI+"-to"), true)
		finishSubject(out)
		startResource(out, mappingIRI+"-from", "https://fno.io/vocabulary/composition/0.1.0/MappingPoint")
		writeSubject(out, "", "https://fno.io/vocabulary/composition/0.1.0/constituentFunction", iri(fragment(document, "function", mapping.From.Function)), true)
		writeSubject(out, "", "https://fno.io/vocabulary/composition/0.1.0/functionOutput", iri(fragment(document, "output", mapping.From.Output)), true)
		finishSubject(out)
		startResource(out, mappingIRI+"-to", "https://fno.io/vocabulary/composition/0.1.0/MappingPoint")
		writeSubject(out, "", "https://fno.io/vocabulary/composition/0.1.0/constituentFunction", iri(fragment(document, "function", mapping.To.Function)), true)
		writeSubject(out, "", "https://fno.io/vocabulary/composition/0.1.0/functionParameter", iri(fragment(document, "parameter", mapping.To.Parameter)), true)
		finishSubject(out)
	}
}

func compileEndpoints(out *strings.Builder, document string, endpoints map[string]Endpoint, prefixes map[string]string) {
	for _, name := range sortedKeys(endpoints) {
		endpoint := endpoints[name]
		startResource(out, fragment(document, "endpoint", name), aggr+"Endpoint")
		writeOptionalLiteral(out, dct+"title", endpoint.Title)
		writeOptionalLiteral(out, dct+"description", endpoint.Description)
		writeExtraProperties(out, document, endpoint.ExtraProperties, prefixes)
		writeSubject(out, "", aggr+"path", literal(endpoint.Path), true)
		operations := make([]string, 0, len(endpoint.Operations))
		for index := range endpoint.Operations {
			operations = append(operations, fmt.Sprintf("%s#operation-%s-%d", document, name, index))
		}
		writeIRIs(out, "http://www.w3.org/ns/hydra/core#supportedOperation", operations)
		finishSubject(out)
		for index, operation := range endpoint.Operations {
			operationIRI := fmt.Sprintf("%s#operation-%s-%d", document, name, index)
			startResource(out, operationIRI, "http://www.w3.org/ns/hydra/core#Operation")
			writeOptionalLiteral(out, dct+"title", operation.Title)
			writeOptionalLiteral(out, dct+"description", operation.Description)
			writeIRIs(out, aggr+"accessRole", roleIRIs(document, operation.AccessRoles))
			writeExtraProperties(out, document, operation.ExtraProperties, prefixes)
			writeSubject(out, "", "http://www.w3.org/ns/hydra/core#method", literal(operation.Method), true)
			if operation.Executes != "" {
				writeSubject(out, "", aggr+"executes", iri(fragment(document, "function", operation.Executes)), true)
			}
			if operation.Updates != nil {
				for _, parameter := range operation.Updates.Parameters {
					writeSubject(out, "", aggr+"updatesParameter", iri(fragment(document, "parameter", parameter)), true)
				}
			}
			finishSubject(out)
		}
	}
}

func writePrefixes(out *strings.Builder) {
	out.WriteString("@prefix aggr: <https://w3id.org/aggregator#> .\n@prefix dcat: <http://www.w3.org/ns/dcat#> .\n@prefix dct: <http://purl.org/dc/terms/> .\n@prefix fno: <https://w3id.org/function/ontology#> .\n@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .\n\n")
}
func startResource(out *strings.Builder, subject, class string) {
	out.WriteString(iri(subject) + " a " + iri(class))
}
func writeSubject(out *strings.Builder, subject, predicate, object string, continuation bool) {
	if subject != "" {
		out.WriteString(iri(subject))
	}
	if continuation {
		out.WriteString(" ;\n    ")
	} else {
		out.WriteString(" ")
	}
	out.WriteString(iri(predicate) + " " + object)
}
func writeOptionalLiteral(out *strings.Builder, predicate, value string) {
	if value != "" {
		writeSubject(out, "", predicate, literal(value), true)
	}
}
func writeExtraProperties(out *strings.Builder, document string, properties map[string]string, prefixes map[string]string) {
	for _, predicate := range sortedKeys(properties) {
		writeSubject(out, "", predicateURI(document, predicate, prefixes), rdfValue(properties[predicate], prefixes), true)
	}
}
func rdfValue(value string, prefixes map[string]string) string {
	if strings.Contains(value, "://") {
		return iri(value)
	}
	if prefix, _, ok := strings.Cut(value, ":"); ok {
		if _, exists := allPrefixes(prefixes)[prefix]; exists {
			return iri(expand(value, prefixes))
		}
	}
	return literal(value)
}
func writeIRIs(out *strings.Builder, predicate string, values []string) {
	if len(values) == 0 {
		return
	}
	objects := make([]string, len(values))
	for i, value := range values {
		objects[i] = iri(value)
	}
	writeSubject(out, "", predicate, strings.Join(objects, ", "), true)
}
func writeList(out *strings.Builder, predicate string, values []string) {
	objects := make([]string, len(values))
	for i, value := range values {
		objects[i] = iri(value)
	}
	writeSubject(out, "", predicate, "( "+strings.Join(objects, " ")+" )", true)
}
func finishSubject(out *strings.Builder)          { out.WriteString(" .\n\n") }
func iri(value string) string                     { return "<" + value + ">" }
func literal(value string) string                 { return strconv.Quote(value) }
func fragment(document, kind, name string) string { return document + "#" + kind + "-" + name }
func refs(document, kind string, names []string) []string {
	values := make([]string, len(names))
	for i, name := range names {
		values[i] = fragment(document, kind, name)
	}
	return values
}
func roleIRIs(document string, names []string) []string { return refs(document, "role", names) }
func predicateURI(document, value string, prefixes map[string]string) string {
	if strings.Contains(value, "://") {
		return value
	}
	if p, l, ok := strings.Cut(value, ":"); ok {
		if base, exists := allPrefixes(prefixes)[p]; exists {
			return base + l
		}
	}
	return document + "#" + value
}
func expand(value string, prefixes map[string]string) string {
	return predicateURI("", value, prefixes)
}
func allPrefixes(custom map[string]string) map[string]string {
	values := map[string]string{"aggr": aggr, "dcat": dcat, "dct": dct, "fno": fno, "xsd": "http://www.w3.org/2001/XMLSchema#", "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#"}
	for k, v := range custom {
		values[k] = v
	}
	return values
}
func keyedIRIs[V any](document, kind string, values map[string]V) []string {
	keys := sortedKeys(values)
	result := make([]string, len(keys))
	for i, key := range keys {
		result[i] = fragment(document, kind, key)
	}
	return result
}
func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
