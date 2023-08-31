package auth_client

import (
	"fmt"
	"net"
)

func getFreeLocalPort() (int, error) {
	port := 49215
	foundOpenPort := false
	for port < 65535 {

		host := fmt.Sprintf("localhost:%d", port)
		Log.Infof("Trying %s", host)
		ln, err := net.Listen("tcp", host)
		if err != nil {
			Log.Debugf("Can't listen on port %d: %s", port, err)
			// move to next port
			port = port + 1
			continue
		}
		_ = ln.Close()
		foundOpenPort = true
		break
	}
	if foundOpenPort == false {
		return 0, NoFreePort
	}
	return port, nil
}
