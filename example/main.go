package main

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"

	auth "github.com/thalesgroupsm/ldk-golang-auth-api"

	"github.com/jessevdk/go-flags"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
)

type Environment struct {
	AuthzUri            string `env:"SNTL_AUTHZ_URI"               default:"http://localhost:8083/realms/myrealm/protocol/openid-connect/auth"  required:"true"    description:"authz uri"                  long:"authz-uri"`
	TokenUri            string `env:"SNTL_TOKEN_URI"               default:"http://localhost:8083/realms/myrealm/protocol/openid-connect/token" required:"true"    description:"token uri"                  long:"token-uri"`
	UserInfoUri         string `env:"SNTL_USER_INFO_URI"           default:""                             required:"false"  description:"user info uri"              long:"user-info-uri"`
	ClientId            string `env:"SNTL_CLIENT_ID"               default:"lms"                          required:"true"   description:"client id"                  long:"client_id"`
	ClientSecret        string `env:"SNTL_CLIENT_SECRET"           default:""                             required:"false"  description:"client secret"              long:"client_secret"`
	RedirectUri         string `env:"SNTL_REDIRECT_URI"            default:"http://localhost/v1/callback" required:"true"   description:"REDIRECT uri"               long:"redirect-uri"`
	LogLevel            string `env:"SNTL_LOG_LEVEL"               default:"INFO"                         required:"true"   description:"log level"                  long:"log-level"`
	VendorId            string `env:"SNTL_VENDOR_ID"               default:"37515"                        required:"true"   description:"vendor id"                  long:"vendor-id"`
	WelcomeFileName     string `env:"SNTL_WELCOME_FILE_NAME"       default:"wlecome.html"                 required:"true"   description:"welcome file name"          long:"welcome-file-name"`
	CodeChallengeMethod string `env:"SNTL_CODE_CHALLENGE_METHOD"   default:"S256"                         required:"true"   description:"code challenge method"      long:"code-challenge-method"`
	Scope               string `env:"SNTL_SCOPE"                   default:"scope"                        required:"true"   description:"profile scope"              long:"scope"`
	GrantType           string `env:"SNTL_GRANT_TYPE"              default:"authorization_code"           required:"true"   description:"grant type"                 long:"grant-type"`
	StoreAuthz          bool   `env:"SNTL_STORE_AUTHZ"                                    required:"false"   description:"store authz"                long:"store-authz"`
}

var (
	Env                        Environment
	Config                     *auth.AuthConfig
	AClient                    *auth.AuthClient
	logger                     = logrus.New()
	Log                        *logrus.Entry
	Version                    = "9.0.0"
	Build                      string
	L                          *LicenseApi
	InvalidCodeChallengeMethod = errors.New("invalid CodeChallengeMethod")
)

func validEnv() error {

	if Env.CodeChallengeMethod != "S256" && Env.CodeChallengeMethod != "plain" {
		Log.Errorf(InvalidCodeChallengeMethod.Error())
		return InvalidCodeChallengeMethod
	}
	return nil

}

func envSetup(env *Environment) error {

	// Log as JSON instead of the default ASCII formatter.
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetOutput(os.Stdout)

	Log = logger.WithFields(logrus.Fields{"App_name": "aut_client_sample", "App_version": Version + "_" + Build})
	// parse & validate environment variables
	godotenv.Load()
	flags.Parse(env)
	err := validEnv()
	if err != nil {
		return err
	}
	env.LogLevel = strings.ToUpper(env.LogLevel)
	switch env.LogLevel {
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
		Log.Errorf("invalid log level: %s", Env.LogLevel)
	}
	return nil
}

func main() {

	err := envSetup(&Env)
	if err != nil {
		Log.Error("auth client sample failed on enviroment setup")
		return
	}
	Log.Infof("auth client sample starting...")
	Config = &auth.AuthConfig{
		ClientId:            Env.ClientId,
		AuthzUri:            Env.AuthzUri,
		TokenUri:            Env.TokenUri,
		RedirectUri:         Env.RedirectUri,
		WelcomeFileName:     Env.WelcomeFileName,
		Scope:               Env.Scope,
		UsePkce:             true,
		CodeChallengeMethod: Env.CodeChallengeMethod,
		GrantType:           Env.GrantType,
		LogLevel:            Env.LogLevel,
		StoreAuthz:          Env.StoreAuthz,
	}

	AClient = auth.NewAuthClient(Config)
	if AClient != nil {
		err = AClient.GetStoredAuthz()
		if err != nil {
			err = AClient.AuthorizeUser(context.Background())
			if err == nil {
				AClient.SetStoredAuthz()
			}
		}

	}
	L = NewLicenseApi(Env.VendorId)
	//hasp_config(accsstoken)
	L.LoginByIdentity("792409087108542559")

}
