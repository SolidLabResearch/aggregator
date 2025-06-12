package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

func main() {
	fileURLs := os.Getenv("FILE_URLS")
	if fileURLs == "" {
		log.Fatal("❌ You must set the FILE_URLS environment variable.")
	}

	outputFileName := "output.txt"
	outputFile, err := os.Create(outputFileName)
	if err != nil {
		log.Fatalf("❌ Failed to create output file: %v", err)
	}
	defer outputFile.Close()

	// Download and concatenate each file
	for _, fileURL := range strings.Split(fileURLs[1:len(fileURLs)-1], " ") {
		fileURL = strings.TrimSpace(fileURL)
		if fileURL == "" {
			continue
		}

		log.Println("📥 Downloading:", fileURL)
		resp, err := http.Get(fileURL)
		if err != nil {
			log.Fatalf("Failed to download file: %v", err)
		}
		defer resp.Body.Close()

		_, err = io.Copy(outputFile, resp.Body)
		if err != nil {
			log.Fatalf("Failed to write to output file: %v", err)
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
