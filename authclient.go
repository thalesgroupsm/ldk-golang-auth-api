package auth_client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	cv "github.com/nirasan/go-oauth-pkce-code-verifier"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var (
	logger              = logrus.New()
	Log                 *logrus.Entry
	Version             = "9.0.0"
	Build               string
	NoFreePort          = errors.New("no free port")
	NotFoundCode        = errors.New("could not find 'code' URL parameter")
	NotFoundAccessToken = errors.New("could not retrieve access token")
	StoreTokenErr       = errors.New("could not store access token")
	GetTokenErr         = errors.New("could not get access token")
)

type AuthClient struct {
	codeChallenge  string
	codeVerifier   *cv.CodeVerifier
	WelcomeHtml    string
	loopBackServer *http.Server
	Aconfig        *AuthConfig
	Atoken         *AuthToken
}

func NewAuthClient(authConfig *AuthConfig) *AuthClient {
	html, err := os.ReadFile("welcome.html")
	if err != nil {
		Log.Errorf("invalid welcome html file, %v", err)
		return nil
	}
	return &AuthClient{
		WelcomeHtml: string(html),
		Aconfig:     authConfig,
	}
}

// AuthorizeUser: implements the PKCE OAuth2 flow.

func (a *AuthClient) AuthorizeUser(ctx context.Context) error {
	a.Aconfig.LogSetup()
	a.Aconfig.SetPkce()

	err := a.Aconfig.SetRedirectUri()
	if err != nil {
		return err
	}

	// initialize the code verifier
	a.codeVerifier, _ = cv.CreateCodeVerifier()

	if a.Aconfig.CodeChallengeMethod == "S256" {
		// Create code_challenge with S256 method
		a.codeChallenge = a.codeVerifier.CodeChallengeS256()
	} else if a.Aconfig.CodeChallengeMethod == "plain" {
		a.codeChallenge = a.codeVerifier.CodeChallengePlain()
	}
	var authorizationURL string
	if a.Aconfig.UsePkce == true {
		authorizationURL = fmt.Sprintf(
			a.Aconfig.AuthzUri+
				"?scope=openid"+
				"&response_type=code&client_id=%s"+
				"&redirect_uri=%s"+
				"&code_challenge=%s"+
				"&code_challenge_method=%s",
			a.Aconfig.ClientId, a.Aconfig.RedirectUri, a.codeChallenge, a.Aconfig.CodeChallengeMethod)
	} else {
		authorizationURL = fmt.Sprintf(
			a.Aconfig.AuthzUri+
				"?scope=openid"+
				"&response_type=code&client_id=%s"+
				"&redirect_uri=%s"+
				"&state=%s",
			a.Aconfig.ClientId, a.Aconfig.RedirectUri, a.Aconfig.State)
	}

	err = a.StartLoopbackService(authorizationURL)
	if err != nil {
		Log.Errorf("Start loopback service err: %v", err)
		return err
	}

	return err
}

// getAccessToken trades the authorization code retrieved from the first OAuth2 leg for an access token
func (a *AuthClient) getAccessToken(authorizationCode string) error {
	var token AuthToken

	// set the url and form-encoded data for the POST to the access token endpoint
	var data string
	if a.Aconfig.UsePkce == true {
		data = fmt.Sprintf(
			"grant_type=%s&client_id=%s"+
				"&code_verifier=%s"+
				"&code=%s"+
				"&redirect_uri=%s",
			a.Aconfig.GrantType, a.Aconfig.ClientId, a.codeVerifier, authorizationCode, a.Aconfig.RedirectUri)
	} else {
		data = fmt.Sprintf(
			"grant_type=%s&client_id=%s"+
				"&client_secret=%s"+
				"&code=%s"+
				"&redirect_uri=%s",
			a.Aconfig.GrantType, a.Aconfig.ClientId, a.Aconfig.ClientSecret, authorizationCode, a.Aconfig.RedirectUri)
	}

	payload := strings.NewReader(data)

	// create the request and execute it
	req, _ := http.NewRequest("POST", a.Aconfig.TokenUri, payload)
	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	req.Header.Add("Connection", "keep-alive")

	client := http.Client{}
	tr := &http.Transport{
		//Proxy: http.ProxyURL(proxyUrl),
	}
	client.Transport = tr
	res, err := client.Do(req)
	if err != nil {
		Log.Errorf("snap: HTTP error: %s", err)
		return err
	}

	// process the response
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)

	// unmarshal the json into a string map
	err = json.Unmarshal(body, &token)
	if err != nil {
		Log.Errorf("snap: JSON error: %s", err)
		return err
	}

	// retrieve the access token out of the map, and return to caller
	if token.AccessToken != "" {
		a.Atoken = &token
		return nil
	}
	return err
}

func (a *AuthClient) GetStoredAuthz() (err error) {
	var token []byte
	err = GetTokenErr
	a.Aconfig.LogSetup()
	if a.Aconfig.StoreAuthz == true {
		viper.SetConfigFile("./auth.json")
		err = viper.ReadInConfig()
		if err != nil {
			return GetTokenErr
		}
		if viper.IsSet("AccessToken") {
			encodeToken := viper.Get("AccessToken")
			if encodeToken != nil {
				token, err = base64.StdEncoding.DecodeString(fmt.Sprintf("%v", encodeToken))
				if err != nil {
					Log.Errorf("decode auth err:%v", err)
				}
				var authToken AuthToken
				err = json.Unmarshal(token, &authToken)
				if err != nil {
					Log.Errorf("invalid auth token:%#v", err)
				} else {
					a.Atoken = &authToken
				}

			}
		} else {
			Log.Errorln("invalid access token file")
		}

	}
	return err

}

func (a *AuthClient) SetStoredAuthz() (err error) {
	a.Aconfig.LogSetup()
	if a.Aconfig.StoreAuthz == true {
		str, err := json.Marshal(a.Atoken)
		viper.Set("AccessToken", base64.StdEncoding.EncodeToString(str))
		err = viper.WriteConfigAs("auth.json")
		if err != nil {
			Log.Error("snap: could not write config file")

			return StoreTokenErr
		}
	}
	return nil

}
