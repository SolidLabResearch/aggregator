package model

type User struct {
	UserId         string
	IDToken        string
	AccessToken    string
	RefreshToken   string
	AuthzServerURL string
}
