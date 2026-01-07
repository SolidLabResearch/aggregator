package registration

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/maartyman/rdfgo"
	"github.com/sirupsen/logrus"
)

// discoverIDPFromWebID discovers the OIDC issuer from a WebID
// In production, this should dereference the WebID document and look for solid:oidcIssuer
func discoverIDPFromWebID(webID string) (string, error) {
	logrus.Debugf("Dereferencing WebID to discover IDP: %s", webID)

	// Create HTTP request to dereference the WebID
	req, err := http.NewRequest("GET", webID, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request for WebID: %w", err)
	}

	// Set Accept headers for RDF formats
	req.Header.Set("Accept", "text/turtle, application/n-quads, application/n-triples")

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to dereference WebID: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("WebID returned status %d", resp.StatusCode)
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read WebID document: %w", err)
	}

	contentType := resp.Header.Get("Content-Type")
	logrus.Debugf("WebID document Content-Type: %s", contentType)

	// Extract base URL (without fragment) for relative URI resolution
	baseURL := webID
	if idx := strings.Index(webID, "#"); idx != -1 {
		baseURL = webID[:idx]
	}

	// Parse RDF using rdfgo with base URL for relative URI resolution
	quadStream, errChan := rdfgo.Parse(
		strings.NewReader(string(body)),
		rdfgo.ParserOptions{
			Format:  contentType,
			BaseIRI: baseURL,
		},
	)

	// Create RDF store
	store := rdfgo.NewStore()

	// Handle parsing errors
	go func() {
		for err := range errChan {
			if err != nil {
				logrus.WithError(err).Warn("Error parsing RDF during WebID dereferencing")
			}
		}
	}()

	// Import quads into store
	store.Import(quadStream)

	// Query for solid:oidcIssuer predicate
	// Look for triples: <webID> solid:oidcIssuer <issuer>
	webIDNode := rdfgo.NewNamedNode(webID)
	oidcIssuerPredicate := rdfgo.NewNamedNode("http://www.w3.org/ns/solid/terms#oidcIssuer")

	matches := rdfgo.Stream(store.Match(webIDNode, oidcIssuerPredicate, nil, nil)).ToArray()

	if len(matches) > 0 {
		issuer := matches[0].GetObject().GetValue()
		logrus.Infof("Discovered IDP from WebID %s: %s", webID, issuer)
		return issuer, nil
	}

	// If no matches found, also try querying with base URL (without fragment)
	if baseURL != webID {
		baseURLNode := rdfgo.NewNamedNode(baseURL)
		matches = rdfgo.Stream(store.Match(baseURLNode, oidcIssuerPredicate, nil, nil)).ToArray()

		if len(matches) > 0 {
			issuer := matches[0].GetObject().GetValue()
			logrus.Infof("Discovered IDP from WebID %s (using base URL): %s", webID, issuer)
			return issuer, nil
		}
	}

	return "", fmt.Errorf("solid:oidcIssuer not found in WebID document for %s", webID)
}
