package main

import (
	"fmt"
	"github.com/maartyman/rdfgo"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

func main() {
	pipelineDescription := os.Getenv("PIPELINE_DESCRIPTION")
	if pipelineDescription == "" {
		log.Fatal("❌ You must set the FILE_URLS environment variable.")
	}
	fmt.Printf("pipelineDescription:\n%s\n", pipelineDescription)
	quadStream, errChan := rdfgo.Parse(strings.NewReader(pipelineDescription), rdfgo.ParserOptions{Format: "turtle"})
	store := rdfgo.NewStore()
	go func() {
		for err := range errChan {
			if err != nil {
				log.Fatalf("❌ Error parsing RDF: %v", err)
			}
		}
	}()
	store.Import(quadStream)

	var fileURLs []string
	listElement := rdfgo.Stream(store.Match(nil, rdfgo.NewNamedNode("http://localhost:5000/config#sources"), nil, nil)).ToArray()[0].GetObject()
	for !listElement.Equals(rdfgo.NewNamedNode("http://www.w3.org/1999/02/22-rdf-syntax-ns#nil")) {
		fileURLs = append(fileURLs, rdfgo.Stream(store.Match(listElement, rdfgo.NewNamedNode("http://www.w3.org/1999/02/22-rdf-syntax-ns#first"), nil, nil)).ToArray()[0].GetObject().GetValue())
		fmt.Printf("📄 Found file URL: %s\n", fileURLs[len(fileURLs)-1])
		listElement = rdfgo.Stream(store.Match(listElement, rdfgo.NewNamedNode("http://www.w3.org/1999/02/22-rdf-syntax-ns#rest"), nil, nil)).ToArray()[0].GetObject()
		fmt.Printf("➡️ Next list element: %s\n", listElement.GetValue())
	}

	outputFileName := "output.txt"
	outputFile, err := os.Create(outputFileName)
	if err != nil {
		log.Fatalf("❌ Failed to create output file: %v", err)
	}
	defer outputFile.Close()

	for _, fileURL := range fileURLs {
		fileURL = strings.TrimSpace(fileURL)
		if fileURL == "" {
			continue
		}

		log.Println("📥 Downloading:", fileURL)
		resp, err := http.Get(fileURL)
		if err != nil {
			log.Fatalf("❌ Failed to download file: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			log.Printf("🔄 Redirect detected: %s -> %s", fileURL, resp.Header.Get("Location"))
			fileURL = resp.Header.Get("Location")
			resp, err = http.Get(fileURL)
			if err != nil {
				log.Fatalf("❌ Failed to follow redirect: %v", err)
			}
			defer resp.Body.Close()
		}

		_, err = io.Copy(outputFile, resp.Body)
		if err != nil {
			log.Fatalf("❌ Failed to write to output file: %v", err)
		}

		// Optionally separate files with a newline
		outputFile.WriteString("\n")
	}

	log.Printf("✅ All files concatenated into %s", outputFileName)

	// Serve only the concatenated file
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Request received", r.Method, r.RequestURI)
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, outputFileName)
	})

	log.Println("🌐 Serving file on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
