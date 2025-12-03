package types

import (
	"aggregator/vars"
	"fmt"
)

type User struct {
	UserId         string
	AccessToken    string
	RefreshToken   string
	AuthzServerURL string
	Namespace      string
}

func (u *User) ConfigEndpoints() map[string]string {
	return map[string]string{
		"actors": fmt.Sprintf("http://%s/config/%s/actors", vars.ExternalHost, u.Namespace),
	}
}
