package config

import (
	"fmt"
	"strings"
)

func negotiateContentType(accept string, supported []string) string {
	if accept == "" || accept == "*/*" {
		return supported[0]
	}

	type mediaTypeWithQuality struct {
		mediaType string
		quality   float64
	}

	var acceptedTypes []mediaTypeWithQuality
	types := strings.Split(accept, ",")

	for _, t := range types {
		parts := strings.Split(t, ";")
		mediaType := strings.TrimSpace(parts[0])
		quality := 1.0

		for _, param := range parts[1:] {
			param = strings.TrimSpace(param)
			if strings.HasPrefix(param, "q=") {
				if q, err := parseQuality(strings.TrimPrefix(param, "q=")); err == nil {
					quality = q
				}
			}
		}

		acceptedTypes = append(acceptedTypes, mediaTypeWithQuality{mediaType, quality})
	}

	var bestMatch string
	var bestQuality float64 = -1

	for _, supportedType := range supported {
		for _, accepted := range acceptedTypes {
			if accepted.mediaType == supportedType || accepted.mediaType == "*/*" {
				if accepted.quality > bestQuality {
					bestQuality = accepted.quality
					bestMatch = supportedType
				}
			}
		}
	}

	return bestMatch
}

func parseQuality(s string) (float64, error) {
	s = strings.TrimSpace(s)
	var q float64
	if _, err := fmt.Sscanf(s, "%f", &q); err != nil {
		return 0, err
	}
	if q < 0 {
		q = 0
	}
	if q > 1 {
		q = 1
	}
	return q, nil
}
