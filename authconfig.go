package auth_client

import (
	"fmt"
	"net/url"
)

type AuthConfig struct {
	AuthzUri            string
	TokenUri            string
	UserInfoUri         string
	ClientId            string
	ClientSecret        string
	State               string
	UsePkce             bool
	CodeChallengeMethod string
	RedirectUri         string
	Scope               string
	SignerKey           string
	GrantType           string
	LogLevel            string
	Port                int
	WelcomeFileName     string
	StoreAuthz          bool
}

func NewAuthConfig() *AuthConfig {

	return &AuthConfig{

		Scope:               "profile",
		UsePkce:             true,
		CodeChallengeMethod: "S256",
		GrantType:           "authorization_code",
	}
}

func (a *AuthConfig) SetPkce() {
	if a.ClientSecret == "" {
		a.UsePkce = true
	} else {
		a.UsePkce = false
		if a.State == "" {
			a.State = "asfwerwsdfw"
		}
	}
	return

}

func (a *AuthConfig) SetRedirectUri() error {
	/*
		When starting the sign-on process, the client library starts an HTTP listener that waits for the OIDC response.
		This listener is started in the first available port in range 49215 - 65535 (IANA suggested range for dynamic or private ports).*/
	var err error
	a.Port, err = getFreeLocalPort()
	if err == nil {
		Log.Infof("TCP Port %d is available\n", a.Port)
		u, err := url.Parse(a.RedirectUri)
		if err != nil {
			Log.Errorf("invalid redirecturi, %v", err)
		}

		a.RedirectUri = fmt.Sprintf(u.Scheme+"://"+u.Host+":%d"+u.Path, a.Port)
	} else {
		Log.Error("Can't find free port")
	}
	return err
}
