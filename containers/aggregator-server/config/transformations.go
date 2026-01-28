package config

import (
	"aggregator/model"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/maartyman/rdfgo"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type TransformationsConfigData struct {
	etagTransformations int
	transformations     []model.Transformation
	store               rdfgo.Store
}

func InitTransformationsConfiguration(mux *http.ServeMux) error {
	logrus.Info("Initializing transformations configuration")

	tfs, err := loadTransformationCRs()
	if err != nil {
		return fmt.Errorf("error loading transformation CRs: %w", err)
	}

	config := TransformationsConfigData{
		etagTransformations: 0,
		transformations:     tfs,
		store:               rdfgo.NewStore(),
	}
	config.updateCatalog()

	// Register HTTP handler
	mux.HandleFunc(model.TransformationCatalog, config.HandleTransformationsEndpoint)

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

	// serialize store to turtle
	var buf bytes.Buffer
	stream := config.store.Match(nil, nil, nil, nil)
	_, err := rdfgo.Write(stream, &buf, rdfgo.WriterOptions{
		Format: "turtle",
	})

	header := w.Header()
	header.Set("ETag", strconv.Itoa(config.etagTransformations))
	header.Set("Content-Type", contentType)
	_, err = w.Write(buf.Bytes())
	if err != nil {
		http.Error(w, "error when writing body", http.StatusInternalServerError)
	}
}

func (config *TransformationsConfigData) updateCatalog() {
	// Clear existing store
	config.store.RemoveMatches(nil, nil, nil, nil)

	// Insert catalog base
	reader := strings.NewReader(catalogBase)
	quads, errChan := rdfgo.Parse(reader, rdfgo.ParserOptions{
		Format:  "turtle",
		BaseIRI: fmt.Sprintf("http://%s/config/transformations#", model.ExternalHost),
	})

	go func() {
		for err := range errChan {
			if err != nil {
				logrus.WithError(err).Warn("Error parsing catalog base")
			}
		}
	}()

	config.store.Import(quads)

	// Insert transformations
	for _, t := range config.transformations {
		reader := strings.NewReader(t.FNO)
		quads, errChan := rdfgo.Parse(reader, rdfgo.ParserOptions{
			Format:  "turtle",
			BaseIRI: fmt.Sprintf("http://%s/config/transformations#", model.ExternalHost),
		})

		go func() {
			for err := range errChan {
				if err != nil {
					logrus.WithError(err).Warn("Error parsing transformation FNO")
				}
			}
		}()

		config.store.Import(quads)

		// Link transformation to catalog
		config.store.AddQuadFromTerms(
			rdfgo.NewNamedNode(fmt.Sprintf("http://%s/config/transformations#transformation-catalog", model.ExternalHost)),
			rdfgo.NewNamedNode("https://spec.knows.idlab.ugent.be/aggregator-protocol/latest/#hasTransformation"),
			rdfgo.NewNamedNode(fmt.Sprintf("http://%s/config/transformations#%s", model.ExternalHost, t.ID)),
			nil,
		)
	}
}

func loadTransformationCRs() ([]model.Transformation, error) {
	gvr := schema.GroupVersionResource{
		Group:    "agg.idlab.ugent.be",
		Version:  "v1",
		Resource: "transformations",
	}

	crList, err := model.DynamicClient.
		Resource(gvr).
		Namespace(model.Namespace).
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
			ID:           getString(spec, "id"),
			Image:        getString(spec, "image"),
			InputMapping: make(map[string]string),
			FNO:          getString(spec, "fno"),
		}

		// inputMapping
		if env, ok := spec["inputMapping"].(map[string]interface{}); ok {
			t.InputMapping = make(map[string]string)
			for k, v := range env {
				t.InputMapping[k] = fmt.Sprint(v)
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

const catalogBase = `
@prefix aggr: <https://spec.knows.idlab.ugent.be/aggregator-protocol/latest/#> .
@prefix fno: <https://w3id.org/function/ontology#> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix dct: <http://purl.org/dc/terms/> .

<transformation-catalog> a aggr:TransformationCollection ;
    dct:title "Aggregator transformations" .
`
