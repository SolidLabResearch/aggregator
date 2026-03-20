package model

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
)

func LogHeaders(prefix string, headers http.Header) {
	safeHeaders := logrus.Fields{}

	for k, v := range headers {
		// Mask sensitive headers
		switch http.CanonicalHeaderKey(k) {
		case "Authorization", "Cookie", "Set-Cookie":
			safeHeaders[k] = "[REDACTED]"
		default:
			safeHeaders[k] = strings.Join(v, ", ")
		}
	}

	logrus.WithFields(safeHeaders).Debug(prefix)
}

func NormalizeHeaders(raw map[string]interface{}) http.Header {
	headers := http.Header{}

	for k, v := range raw {
		switch vv := v.(type) {
		case string:
			headers.Add(k, vv)
		case []interface{}:
			for _, item := range vv {
				if s, ok := item.(string); ok {
					headers.Add(k, s)
				}
			}
		default:
			headers.Add(k, fmt.Sprintf("%v", vv))
		}
	}

	return headers
}
