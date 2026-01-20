package config

import (
	"aggregator/model"
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type TransformationsConfigData struct {
	etagTransformations int
	transformations     []model.Transformation
	fno                 string
}

func InitTransformationsConfiguration(mux *http.ServeMux) error {
	logrus.Info("Initializing transformations configuration")

	tfs, err := loadTransformationCRs()
	if err != nil {
		return fmt.Errorf("error loading transformation CRs: %w", err)
	}
	fno, err := buildUnifiedFNO(tfs)
	if err != nil {
		return fmt.Errorf("error building unified FNO: %w", err)
	}

	config := TransformationsConfigData{
		etagTransformations: 0,
		transformations:     tfs,
		fno:                 fno,
	}

	// Register HTTP handler
	mux.HandleFunc("/config/transformations", config.HandleTransformationsEndpoint)

	logrus.Info("Transformations configuration initialization completed")
	return nil
}

// HandleTransformationsEndpoint handles requests to the /config/transformations endpoint
func (config TransformationsConfigData) HandleTransformationsEndpoint(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "HEAD":
		config.headAvailableTransformations(w, r)
	case "GET":
		config.getAvailableTransformations(w, r)
	default:
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

// getAvailableTransformations HEAD /config/transformations retrieves all available transformations
func (config *TransformationsConfigData) headAvailableTransformations(w http.ResponseWriter, r *http.Request) {
	accept := r.Header.Get("Accept")
	contentType := negotiateContentType(accept, []string{"text/turtle"})

	if contentType == "" {
		http.Error(w, "Unsupported Media Type. Only text/turtle is supported.", http.StatusUnsupportedMediaType)
		return
	}

	header := w.Header()
	header.Set("ETag", strconv.Itoa(config.etagTransformations))
	header.Set("Content-Type", contentType)
}

// getAvailableTransformations GET /config/transformations retrieves all available transformations
func (config *TransformationsConfigData) getAvailableTransformations(w http.ResponseWriter, r *http.Request) {
	accept := r.Header.Get("Accept")
	contentType := negotiateContentType(accept, []string{"text/turtle"})

	if contentType == "" {
		http.Error(w, "Unsupported Media Type. Only text/turtle is supported.", http.StatusUnsupportedMediaType)
		return
	}

	header := w.Header()
	header.Set("ETag", strconv.Itoa(config.etagTransformations))
	header.Set("Content-Type", contentType)
	_, err := w.Write([]byte(config.fno))
	if err != nil {
		http.Error(w, "error when writing body", http.StatusInternalServerError)
	}
}

func loadTransformationCRs() ([]model.Transformation, error) {
	gvr := schema.GroupVersionResource{
		Group:    "fno.knows.idlab.ugent.be",
		Version:  "v1",
		Resource: "transformations",
	}

	crList, err := model.DynamicClient.
		Resource(gvr).
		Namespace("aggregator-app").
		List(context.TODO(), v1.ListOptions{})

	if err != nil {
		return nil, err
	}

	var results []model.Transformation

	for _, item := range crList.Items {
		spec, ok := item.Object["spec"].(map[string]interface{})
		if !ok {
			continue
		}

		t := model.Transformation{
			ID:         getString(spec, "id"),
			Image:      getString(spec, "image"),
			EnvMapping: make(map[string]string),
			FNO:        getString(spec, "fno"),
		}

		// envMapping
		if env, ok := spec["envMapping"].(map[string]interface{}); ok {
			t.EnvMapping = make(map[string]string)
			for k, v := range env {
				t.EnvMapping[k] = fmt.Sprint(v)
			}
		}

		results = append(results, t)
	}

	return results, nil
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		return fmt.Sprint(v)
	}
	return ""
}

func splitFNO(tf model.Transformation) (prefixes []string, body string) {
	lines := strings.Split(tf.FNO, "\n")
	var bodyLines []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "@prefix") {
			prefixes = append(prefixes, line)
		} else if line != "" {
			bodyLines = append(bodyLines, line)
		}
	}

	return prefixes, strings.Join(bodyLines, "\n")
}

func mergePrefixes(allPrefixes [][]string) (map[string]string, error) {
	prefixMap := make(map[string]string)

	for _, prefixList := range allPrefixes {
		for _, p := range prefixList {
			parts := strings.Fields(p)
			if len(parts) < 3 {
				return nil, fmt.Errorf("invalid prefix line: %s", p)
			}

			name := parts[1]
			iri := parts[2]

			if existing, ok := prefixMap[name]; ok {
				if existing != iri {
					return nil, fmt.Errorf(
						"prefix conflict for %s: %s vs %s",
						name, existing, iri,
					)
				}
			} else {
				prefixMap[name] = iri
			}
		}
	}

	return prefixMap, nil
}

func buildUnifiedFNO(tfs []model.Transformation) (string, error) {
	var allPrefixes [][]string
	var bodies []string

	for _, tf := range tfs {
		prefixes, body := splitFNO(tf)
		allPrefixes = append(allPrefixes, prefixes)
		bodies = append(bodies, body)
	}

	prefixMap, err := mergePrefixes(allPrefixes)
	if err != nil {
		return "", err
	}

	var out strings.Builder

	// Add @base
	out.WriteString(fmt.Sprintf(
		"@base <http://%s/config/transformations#> .\n\n",
		model.ExternalHost,
	))

	// Add merged prefixes
	for name, iri := range prefixMap {
		out.WriteString(fmt.Sprintf("@prefix %s %s .\n", name, iri))
	}

	out.WriteString("\n")

	// Add all bodies
	for _, body := range bodies {
		out.WriteString(body)
		out.WriteString("\n\n")
	}

	return out.String(), nil
}
