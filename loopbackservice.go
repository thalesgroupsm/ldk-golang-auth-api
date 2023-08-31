package auth_client

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"

	"github.com/skratchdot/open-golang/open"
)

// cleanup closes the HTTP server
func cleanup(server *http.Server) {
	// we run this as a goroutine so that this function falls through and
	// the socket to the browser gets flushed/closed before the server goes away
	go server.Close()
}
func (a *AuthClient) loopBackHandler(w http.ResponseWriter, r *http.Request) {
	// get the authorization code
	code := r.URL.Query().Get("code")
	if code == "" {
		Log.Error("snap: Url Param 'code' is missing")
		io.WriteString(w, NotFoundCode.Error())

		// close the HTTP server and return
		cleanup(a.loopBackServer)
		return
	}

	// trade the authorization code and the code verifier for an access token
	err := a.getAccessToken(code)
	if err != nil {
		Log.Error("snap: could not get access token")
		io.WriteString(w, NotFoundAccessToken.Error())

		// close the HTTP server and return
		cleanup(a.loopBackServer)
		return
	}

	// return an indication of success to the caller
	io.WriteString(w, a.WelcomeHtml)
	Log.Info("Successfully logged into licensed application API.")

	// close the HTTP server
	cleanup(a.loopBackServer)
}

func (a *AuthClient) StartLoopbackService(authorizationURL string) error {
	// start a web server to listen on a callback URL
	a.loopBackServer = &http.Server{Addr: a.Aconfig.RedirectUri}

	// define a handler that will get the authorization code, call the token endpoint, and close the HTTP server
	http.HandleFunc("/v1/callback", a.loopBackHandler)

	// parse the redirect URL for the port number
	u, err := url.Parse(a.Aconfig.RedirectUri)
	if err != nil {
		Log.Errorf("licensed application: bad redirect URL: %s\n", err)
		return err
	}

	// set up a listener on the redirect port
	port := fmt.Sprintf(":%s", u.Port())
	l, err := net.Listen("tcp", port)
	if err != nil {
		Log.Errorf("licensed application: can't listen to port %s: %s\n", port, err)
		return err
	}
	// open a browser window to the authorizationURL
	err = open.Start(authorizationURL)
	if err != nil {
		Log.Errorf("licensed application: can't open browser to URL %s: %s\n", authorizationURL, err)
		return err
	}

	// start the blocking web server loop
	// this will exit when the handler gets fired and calls server.Close()
	a.loopBackServer.Serve(l)
	return err
}
