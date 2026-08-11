package model

import (
	"strings"
	"sync"
)

type Scope string

const odrlActionPrefix = "http://www.w3.org/ns/odrl/2/"

const (
	Read    Scope = odrlActionPrefix + "read"
	Create  Scope = odrlActionPrefix + "create"
	Delete  Scope = odrlActionPrefix + "delete"
	Write   Scope = odrlActionPrefix + "write"
	Execute Scope = odrlActionPrefix + "execute"
	Modify  Scope = odrlActionPrefix + "modify"
)

var authorizationScopes = struct {
	sync.RWMutex
	resources map[string]map[string][]Scope
}{resources: map[string]map[string][]Scope{}}

func SetAuthorizationScopes(resourceID string, methodScopes map[string][]Scope) {
	copyByMethod := make(map[string][]Scope, len(methodScopes))
	for method, scopes := range methodScopes {
		copyByMethod[strings.ToUpper(method)] = append([]Scope(nil), scopes...)
	}
	authorizationScopes.Lock()
	authorizationScopes.resources[resourceID] = copyByMethod
	authorizationScopes.Unlock()
}

func AuthorizationScopes(resourceID, method string) []Scope {
	authorizationScopes.RLock()
	scopes := append([]Scope(nil), authorizationScopes.resources[resourceID][strings.ToUpper(method)]...)
	authorizationScopes.RUnlock()
	return scopes
}

func DeleteAuthorizationScopes(resourceID string) {
	authorizationScopes.Lock()
	delete(authorizationScopes.resources, resourceID)
	authorizationScopes.Unlock()
}
