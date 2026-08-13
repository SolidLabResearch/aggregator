package auth

import (
	"fmt"

	"github.com/maartyman/rdfgo"
	"github.com/sirupsen/logrus"
)

type Scope string

const (
	Read    Scope = OdrlPrefix + "read"
	Create  Scope = OdrlPrefix + "create"
	Delete  Scope = OdrlPrefix + "delete"
	Write   Scope = OdrlPrefix + "write"
	Execute Scope = OdrlPrefix + "execute"
	Modify  Scope = OdrlPrefix + "modify"
)

func stringsToScopes(scopeStrings []string) []Scope {
	scopes := make([]Scope, len(scopeStrings))
	for i, s := range scopeStrings {
		scopes[i] = Scope(s)
	}
	return scopes
}

func scopeToAction(scope Scope) rdfgo.INamedNode {
	if scope == "" {
		return nil
	}
	return rdfgo.NewNamedNode(string(scope))
}

func requestedScopes(explicit, available []Scope, method string) ([]Scope, error) {
	if len(explicit) == 0 {
		return determineScopes(method, available)
	}
	availableSet := make(map[Scope]bool, len(available))
	for _, scope := range available {
		availableSet[scope] = true
	}
	var selected Scope
	for _, scope := range explicit {
		if !availableSet[scope] {
			return nil, fmt.Errorf("scope %q is not registered for this resource", scope)
		}
		if scope == Execute {
			selected = Execute
		} else if selected == "" && scope != "" {
			selected = scope
		}
	}
	if selected == "" {
		return nil, fmt.Errorf("no authorization scopes requested")
	}
	return []Scope{selected}, nil
}

func determineScopes(method string, resourceScopes []Scope) ([]Scope, error) {
	switch method {
	case "POST":
		for _, scope := range resourceScopes {
			if scope == Create {
				logrus.WithFields(logrus.Fields{"method": method}).Debug("🔧 Requesting 'create' permissions")
				return []Scope{Create}, nil
			}
		}
		logrus.WithFields(logrus.Fields{"method": method}).Debug("🔧 Requesting 'write' permissions")
		return []Scope{Write}, nil
	case "PUT", "PATCH":
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
