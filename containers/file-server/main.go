package main

import (
	"github.com/maartyman/rdfgo"
	"github.com/sirupsen/logrus"
	"io"
	"net/http"
	"os"
	"strings"
)

func main() {
	logLevelValue := os.Getenv("LOG_LEVEL")
	logLevel, err := logrus.ParseLevel(strings.ToLower(logLevelValue))
	if err != nil {
		logLevel = logrus.InfoLevel
	}
	logrus.SetLevel(logLevel)
	logrus.SetOutput(os.Stdout)

	pipelineDescription := os.Getenv("PIPELINE_DESCRIPTION")
	if pipelineDescription == "" {
		logrus.Error("❌ You must set the FILE_URLS environment variable.")
		os.Exit(1)
	}
	logrus.WithFields(logrus.Fields{"pipeline_description": pipelineDescription}).Debug("Pipeline description loaded")
	quadStream, errChan := rdfgo.Parse(strings.NewReader(pipelineDescription), rdfgo.ParserOptions{Format: "turtle"})
	store := rdfgo.NewStore()
	go func() {
		for err := range errChan {
			if err != nil {
				logrus.WithFields(logrus.Fields{"err": err}).Error("❌ Error parsing RDF")
				os.Exit(1)
			}
		}
	}()
	store.Import(quadStream)

	var fileURLs []string
	listElement := rdfgo.Stream(store.Match(nil, rdfgo.NewNamedNode("http://localhost:5000/config#sources"), nil, nil)).ToArray()[0].GetObject()
	for !listElement.Equals(rdfgo.NewNamedNode("http://www.w3.org/1999/02/22-rdf-syntax-ns#nil")) {
		fileURLs = append(fileURLs, rdfgo.Stream(store.Match(listElement, rdfgo.NewNamedNode("http://www.w3.org/1999/02/22-rdf-syntax-ns#first"), nil, nil)).ToArray()[0].GetObject().GetValue())
		logrus.WithFields(logrus.Fields{"url": fileURLs[len(fileURLs)-1]}).Info("📄 Found file URL")
		listElement = rdfgo.Stream(store.Match(listElement, rdfgo.NewNamedNode("http://www.w3.org/1999/02/22-rdf-syntax-ns#rest"), nil, nil)).ToArray()[0].GetObject()
		logrus.WithFields(logrus.Fields{"value": listElement.GetValue()}).Debug("➡️ Next list element")
	}

	outputFileName := "output.txt"
	outputFile, err := os.Create(outputFileName)
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("❌ Failed to create output file")
		os.Exit(1)
	}
	defer outputFile.Close()

	for _, fileURL := range fileURLs {
		fileURL = strings.TrimSpace(fileURL)
		if fileURL == "" {
			continue
		}

		logrus.WithFields(logrus.Fields{"url": fileURL}).Info("📥 Downloading file")
		resp, err := http.Get(fileURL)
		if err != nil {
			logrus.WithFields(logrus.Fields{"err": err, "url": fileURL}).Error("❌ Failed to download file")
			os.Exit(1)
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			logrus.WithFields(logrus.Fields{"from": fileURL, "to": resp.Header.Get("Location")}).Info("🔄 Redirect detected")
			fileURL = resp.Header.Get("Location")
			resp, err = http.Get(fileURL)
			if err != nil {
				logrus.WithFields(logrus.Fields{"err": err, "url": fileURL}).Error("❌ Failed to follow redirect")
				os.Exit(1)
			}
			defer resp.Body.Close()
		}

		_, err = io.Copy(outputFile, resp.Body)
		if err != nil {
			logrus.WithFields(logrus.Fields{"err": err}).Error("❌ Failed to write to output file")
			os.Exit(1)
		}

		// Optionally separate files with a newline
		outputFile.WriteString("\n")
	}

	logrus.WithFields(logrus.Fields{"output_file": outputFileName}).Info("✅ All files concatenated")

	// Serve only the concatenated file
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		logrus.WithFields(logrus.Fields{"method": r.Method, "request_uri": r.RequestURI}).Info("Request received")
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, outputFileName)
	})

	logrus.WithFields(logrus.Fields{"port": 8080}).Info("🌐 Serving file")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		logrus.WithFields(logrus.Fields{"err": err}).Error("File server failed")
		os.Exit(1)
	}
}
