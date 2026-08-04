package model

import (
	"aggregator/util"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/maartyman/rdfgo"
)

type DeploymentRequest struct {
	Bindings   map[string]rdfgo.ITerm
	Definition *ResolvedDeployment
}

func LoadDeploymentFunction(uri string) (*ResolvedDeployment, error) {
	id, err := util.StripPrefix(uri, ExternalServerURL()+DeploymentCatalog+"/")
	if err != nil {
		return nil, fmt.Errorf("invalid deployment function URI %q: %w", uri, err)
	}
	if id == "" || strings.Contains(id, "/") {
		return nil, fmt.Errorf("invalid deployment function URI %q", uri)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	bundle, err := FetchDeploymentBundle(ctx, id)
	if err != nil {
		return nil, err
	}
	return ResolveDeploymentBundle(uri, bundle)
}
