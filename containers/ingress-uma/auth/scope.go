package auth

import (
	"fmt"

	"github.com/maartyman/rdfgo"
	"github.com/sirupsen/logrus"
)

type Scope string

const (
	Read   Scope = "urn:example:css:modes:read"
	Create Scope = "urn:example:css:modes:create"
	Delete Scope = "urn:example:css:modes:delete"
	Write  Scope = "urn:example:css:modes:write"
)

func stringsToScopes(scopeStrings []string) []Scope {
	scopes := make([]Scope, len(scopeStrings))
	for i, s := range scopeStrings {
		scopes[i] = Scope(s)
	}
	return scopes
}

func scopeToAction(scope Scope) rdfgo.INamedNode {
	switch scope {
	case Read:
		return rdfgo.NewNamedNode(OdrlPrefix + "read")
	case Write:
		return rdfgo.NewNamedNode(OdrlPrefix + "write")
	case Create:
		return rdfgo.NewNamedNode(OdrlPrefix + "create")
	case Delete:
		return rdfgo.NewNamedNode(OdrlPrefix + "delete")
	default:
		return nil
	}
}

func determineScopes(method string) ([]Scope, error) {
	switch method {
	case "POST":
		logrus.WithFields(logrus.Fields{"method": method}).Debug("🔧 Requesting 'create' permissions")
		return []Scope{Create}, nil
	case "PUT":
		logrus.WithFields(logrus.Fields{"method": method}).Debug("🔧 Requesting 'write' permissions")
		return []Scope{Write}, nil
	case "DELETE":
		logrus.WithFields(logrus.Fields{"method": method}).Debug("🔧 Requesting 'delete' permissions")
		return []Scope{Delete}, nil
	case "GET", "HEAD":
		logrus.WithFields(logrus.Fields{"method": method}).Debug("📖 Requesting 'read' permissions")
		return []Scope{Read}, nil
	default:
		logrus.WithFields(logrus.Fields{"method": method}).Warn("❌ Method not supported by authorization")
		return nil, fmt.Errorf("❌ Method %s not supported by authorization", method)
	}
}

func checkScopes(permissionedScopes, requiredScopes []Scope) bool {
	permMap := make(map[Scope]struct{}, len(permissionedScopes))
	for _, s := range permissionedScopes {
		permMap[s] = struct{}{}
	}

	// Ensure every required scope exists in the permissioned set
	for _, req := range requiredScopes {
		if _, ok := permMap[req]; !ok {
			return false
		}
	}

	return true
}
