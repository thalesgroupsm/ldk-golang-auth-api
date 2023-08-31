package auth_client

import (
	"io"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

func (a *AuthConfig) LogSetup() {

	if Log != nil {
		return
	}
	// Log as JSON instead of the default ASCII formatter.
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetOutput(os.Stdout)

	Log = logger.WithFields(logrus.Fields{"App_name": "auth_client", "App_version": Version + "_" + Build})

	a.LogLevel = strings.ToUpper(a.LogLevel)
	switch a.LogLevel {
	case "DEBUG":
		logger.SetLevel(logrus.DebugLevel)
		file, err := os.OpenFile("logrus.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err == nil {
			mw := io.MultiWriter(os.Stdout, file)
			logger.SetOutput(mw)
		}
		break
	case "TRACE":
		logger.SetLevel(logrus.TraceLevel)
		break
	case "WARN":
		logger.SetLevel(logrus.WarnLevel)
		break
	case "ERROR":
		logger.SetLevel(logrus.ErrorLevel)
		break
	case "FATAL":
		logger.SetLevel(logrus.FatalLevel)
		break
	case "PANIC":
		logger.SetLevel(logrus.PanicLevel)
		break
	case "INFO":
		logger.SetLevel(logrus.InfoLevel)
		break
	default:
		Log.Errorf("invalid log level: %s", a.LogLevel)
	}
}
