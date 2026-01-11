package model

import (
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
		"services": fmt.Sprintf("http://%s/config/%s/services", ExternalHost, u.Namespace),
	}
}
