package auth_client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/user"
	"strings"

	keyTar "github.com/thalesgroupsm/ldk-golang-auth-api/keytar"

	cv "github.com/nirasan/go-oauth-pkce-code-verifier"
	"github.com/sirupsen/logrus"
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
	GetAccessTokenErr   = errors.New("could not get access token")
	GetRefreshTokenErr  = errors.New("could not get refresh token")
)

type AuthClient struct {
	codeChallenge  string
	codeVerifier   *cv.CodeVerifier
	WelcomeHtml    string
	loopBackServer *http.Server
	Aconfig        *AuthConfig
	Atoken         *AuthToken
	KeytarAccount  string
	KeytarService  string
}

func NewAuthClient(authConfig *AuthConfig) *AuthClient {
	html, err := os.ReadFile("welcome.html")
	if err != nil {
		Log.Errorf("invalid welcome html file, %v", err)
		return nil
	}
	user, err := user.Current()
	if err != nil {
		Log.Errorf("invalid current user, %v", err)
		return nil
	}
	return &AuthClient{
		WelcomeHtml:   string(html),
		Aconfig:       authConfig,
		KeytarAccount: user.Username,
		KeytarService: authConfig.AuthzUri,
	}
}
func (a *AuthClient) refreshTokens() error {
	var token AuthToken
	data := fmt.Sprintf(
		"grant_type=refresh_token&client_id=%s"+
			"&refresh_token=%s",
		a.Aconfig.ClientId, a.Atoken.RefreshToken)

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

	// retrieve the access token out of the map, and return to caller
	if token.AccessToken != "" {
		a.Atoken = &token
		return nil
	}
	return GetRefreshTokenErr
}

// AuthorizeUser: implements the PKCE OAuth2 flow.

func (a *AuthClient) AuthorizeUser(ctx context.Context) error {
	var err error
	a.Aconfig.LogSetup()
	a.Aconfig.SetPkce()
	if a.Atoken != nil && a.Atoken.RefreshToken != "" {
		err = a.refreshTokens()
		if err == nil {
			Log.Infof("refresh token success!")
			return nil
		}
	}
	err = a.Aconfig.SetRedirectUri()
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
				"?response_type=code&client_id=%s"+
				"&redirect_uri=%s"+
				"&code_challenge=%s"+
				"&code_challenge_method=%s",
			a.Aconfig.ClientId, a.Aconfig.RedirectUri, a.codeChallenge, a.Aconfig.CodeChallengeMethod)
	} else {
		authorizationURL = fmt.Sprintf(
			a.Aconfig.AuthzUri+
				"?response_type=code&client_id=%s"+
				"&redirect_uri=%s"+
				"&state=%s",
			a.Aconfig.ClientId, a.Aconfig.RedirectUri, a.Aconfig.State)
	}
	if a.Aconfig.Scope != "" {
		authorizationURL = fmt.Sprintf(authorizationURL+"&scope=%s", a.Aconfig.Scope)
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

	err = GetAccessTokenErr
	var password string
	var authToken AuthToken
	var keychain keyTar.Keychain
	a.Aconfig.LogSetup()
	if a.Aconfig.StoreAuthz == true {
		// Create a keychain
		keychain, err = keyTar.GetKeychain()
		if err != nil {
			Log.Errorf("unable to create keychain, %s", err)
			return err
		}

		// Test that a non-existent lookup fail
		password, err = keychain.GetPassword(
			a.KeytarService,
			a.KeytarAccount,
		)
		if password == "" || err != nil {
			Log.Errorf("retrieval of non-existent service/account password succeeded, %s", err)
		} else {
			authToken.RefreshToken = password
			a.Atoken = &authToken
		}

	}
	return err

}

func (a *AuthClient) SetStoredAuthz() (err error) {
	a.Aconfig.LogSetup()
	if a.Aconfig.StoreAuthz == true && a.Atoken != nil && a.Atoken.RefreshToken != "" {

		// Create a keychain
		keychain, err := keyTar.GetKeychain()
		if err != nil {
			Log.Errorf("unable to create keychain, %s", err)
			return err
		}
		// Add a password
		err = keyTar.ReplacePassword(keychain, a.KeytarService, a.KeytarAccount, a.Atoken.RefreshToken)
		if err != nil {
			Log.Errorf("access token addition failed")
			return err
		}

	}
	return nil

}
