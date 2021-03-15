package config

import (
	"fa-middleware/models"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/FusionAuth/go-client/pkg/fusionauth"
	viper "github.com/spf13/viper"
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

type StripeProduct struct {
	ProductID string   `yaml:"productId"`
	PriceIDs  []string `yaml:"priceIds"`
}

type Config struct {
	Domain                      string                       `yaml:"domain"`
	FullDomainURL               string                       `yaml:"fullDomainURL"`
	FusionAuthHost              string                       `yaml:"fusionAuthHost"`       // "http://fusionauth:9011"
	FusionAuthPublicHost        string                       `yaml:"fusionAuthPublicHost"` // "http://localhost:9011"
	FusionAuthAPIKey            string                       `yaml:"fusionAuthAPIKey"`
	FusionAuthAppID             string                       `yaml:"fusionAuthAppID"`
	FusionAuthOauthRedirectURL  string                       `yaml:"fusionAuthOauthRedirectURL"`
	FusionAuthOauthClientID     string                       `yaml:"fusionAuthOauthClientID"`
	FusionAuthOauthClientSecret string                       `yaml:"fusionAuthOauthClientSecret"`
	FusionAuthTenantID          string                       `yaml:"fusionAuthTenantID"`
	PostgresUser                string                       `yaml:"postgresUser"`
	PostgresPass                string                       `yaml:"postgresPass"`
	PostgresHost                string                       `yaml:"postgresHost"`
	PostgresPort                string                       `yaml:"postgresPort"`
	PostgresDBName              string                       `yaml:"postgresDbName"`
	PostgresOptions             string                       `yaml:"postgresOptions"`
	JWTCookieDomain             string                       `yaml:"jwtCookieDomain"`
	JWTCookieMaxAgeSeconds      int                          `yaml:"jwtCookieMaxAgeSeconds"`
	JWTCookieSetSecure          bool                         `yaml:"jwtCookieSetSecure"` // sets the "secure" flag for the jwt cookie
	JWTCookieName               string                       `yaml:"jwtCookieName"`      // sets the "secure" flag for the jwt cookie
	StripePublicKey             string                       `yaml:"stripePublicKey"`
	StripeSecretKey             string                       `yaml:"stripeSecretKey"`
	StripeProducts              []StripeProduct              `yaml:"stripeProducts"`
	MutationKey                 string                       `yaml:"mutationKey"`
	MutableFields               models.MutableFields         `yaml:"mutableFields"`
	RuntimeOauthState           string                       // will be set later
	FusionAuthClient            *fusionauth.FusionAuthClient // will be set later
	OauthConfig                 *oauth2.Config               // will be set later
	OauthStr                    string                       // will be set later
	CodeVerif                   string                       // will be set later
	CodeChallenge               string                       // will be set later
	AuthCodeURL                 string                       // will be set later
	StripeProductsFromAPI       []models.ProductSummary      // will be set later
}

type CompleteConfig struct {
	Applications []Config     `yaml:"apps"`
	Global       GlobalConfig `yaml:"global"`
}

// LoadConfig reads from a provided yaml-formatted configuration filename
func LoadConfigYaml() (conf CompleteConfig, err error) {
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

// LoadConfig reads from a provided yaml-formatted configuration filename
// TODO: Figureout why this doesn't support the config structs from above.
//       For some reason the "apps" section is empty. Could be related to the
//       un-yaml-annotated sections in the config.
func LoadConfig() (conf CompleteConfig, err error) {
	err = viper.BindEnv("config")
	if err != nil {
		return conf, fmt.Errorf("failed to bind config env: %v", err.Error())
	}
	configName := viper.GetString("config")
	viper.SetConfigName(configName) // name of config file (without extension)
	viper.SetConfigType("yaml")     // REQUIRED if the config file does not have the extension in the name
	viper.AddConfigPath("./res")    // optionally look for config in the working directory
	viper.AddConfigPath(".")        // optionally look for config in the working directory
	err = viper.ReadInConfig()      // Find and read the config file
	if err != nil {                 // Handle errors reading the config file
		return conf, fmt.Errorf("error config file: %s", err)
	}
	err = viper.Unmarshal(&conf)
	if err != nil {
		return conf, fmt.Errorf("unable to decode into struct, %v", err)
	}

	return conf, nil
}

func (conf *CompleteConfig) GetConfigForDomain(domain string) (Config, bool) {
	for _, app := range conf.Applications {
		if app.Domain == domain {
			return app, true
		}
	}

	return Config{}, false
}
