package config

import (
	"fa-middleware/models"

	"fmt"
	"io/ioutil"
	"os"

	"github.com/FusionAuth/go-client/pkg/fusionauth"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v2"
)

const (
	ConfigFile = "config.yml"
)

type GlobalConfig struct {
	BindAddr         string `yaml:"bindAddr"`
	BindPort         int    `yaml:"bindPort"`
	BindPortExternal int    `yaml:"bindPortExternal"`
}

type FusionAuthConfig struct {
	AuthCallbackRedirectURL string                       `yaml:"authCallbackRedirectURL"`
	InternalHostURL         string                       `yaml:"internalHostUrl"` // "http://fusionauth:9011"
	PublicHostURL           string                       `yaml:"publicHostUrl"`   // "http://localhost:9011"
	APIKey                  string                       `yaml:"apiKey"`
	AppID                   string                       `yaml:"appID"`
	OauthRedirectURL        string                       `yaml:"oauthRedirectURL"`
	OauthClientID           string                       `yaml:"oauthClientID"`
	OauthClientSecret       string                       `yaml:"oauthClientSecret"`
	TenantID                string                       `yaml:"tenantID"`
	Client                  *fusionauth.FusionAuthClient // in-memory runtime instance of FusionAuth; is set automatically
}

type JWTConfig struct {
	CookieDomain        string `yaml:"cookieDomain"`
	CookieMaxAgeSeconds int    `yaml:"cookieMaxAgeSeconds"`
	CookieSetSecure     bool   `yaml:"cookieSetSecure"` // sets the "secure" flag for the jwt cookie
	CookieName          string `yaml:"cookieName"`      // sets the "secure" flag for the jwt cookie
}

type StripeConfig struct {
	PublicKey         string                 `yaml:"publicKey"`
	SecretKey         string                 `yaml:"secretKey"`
	PaymentSuccessURL string                 `yaml:"paymentSuccessURL"`
	PaymentCancelURL  string                 `yaml:"paymentCancelURL"`
	Products          []models.StripeProduct `yaml:"products"`
}

// Oauth2Config is set automatically when this program starts up, based on
// values set elsewhere
type Oauth2Config struct {
	AuthCodeURL       string         // will be set later
	CodeChallenge     string         // will be set later
	CodeVerif         string         // will be set later
	OauthConfig       *oauth2.Config // will be set later
	OauthStr          string         // will be set later
	RuntimeOauthState string         // will be set later
}

type App struct {
	Domain                string                  `yaml:"domain"`
	FullDomainURL         string                  `yaml:"fullDomainURL"`
	FusionAuth            FusionAuthConfig        `yaml:"fusionAuth"`
	JWT                   JWTConfig               `yaml:"jwt"`
	Stripe                StripeConfig            `yaml:"stripe"`
	APIKey                string                  `yaml:"apiKey"`
	Oauth2Config          Oauth2Config            // will be set later
	StripeProductsFromAPI []models.ProductSummary // will be set later
}

type Config struct {
	Apps   []App        `yaml:"apps"`
	Global GlobalConfig `yaml:"global"`
}

// LoadConfig reads from a provided yaml-formatted configuration filename
func LoadConfigYaml() (conf Config, err error) {
	confFile := "/res/config.yml"
	envConfFile := os.Getenv("config")
	if envConfFile != "" {
		confFile = envConfFile
	}

	// read from config file
	confData, err := ioutil.ReadFile(confFile)
	if err != nil {
		return conf, fmt.Errorf("failed to read config file %v: %v", confFile, err.Error())
	}

	err = yaml.Unmarshal(confData, &conf)
	if err != nil {
		return conf, fmt.Errorf("failed to parse config file %v: %v", confFile, err.Error())
	}

	return conf, nil
}

func (conf *Config) GetAppByDomain(domain string) (App, bool) {
	for _, app := range conf.Apps {
		if app.Domain == domain {
			return app, true
		}
	}

	return App{}, false
}

func (conf *Config) GetAppByOrigin(origin string) (App, bool) {
	for _, app := range conf.Apps {
		if app.Domain == origin {
			return app, true
		}
	}

	return App{}, false
}

func (conf *Config) GetConfigForAppID(appID string) (App, bool) {
	for _, app := range conf.Apps {
		if app.FusionAuth.AppID == appID {
			return app, true
		}
	}

	return App{}, false
}
