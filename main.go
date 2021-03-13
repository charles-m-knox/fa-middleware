package main

import (
	"fa-middleware/config"
	"fa-middleware/htmltemplates"
	"fa-middleware/routes"

	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/FusionAuth/go-client/pkg/fusionauth"
	"github.com/gin-gonic/gin"
	cv "github.com/nirasan/go-oauth-pkce-code-verifier"
	"github.com/thanhpk/randstr"
	"golang.org/x/oauth2"
)

func main() {
	// load config
	// conf, err := config.LoadConfig()
	// if err != nil {
	// 	log.Fatalf("failed to load config: %v", err.Error())
	// }

	conf, err := config.LoadConfigYaml()
	if err != nil {
		log.Fatalf("failed to load config2: %v", err.Error())
	}

	for i, app := range conf.Applications {
		// initialize oauth state
		conf.Applications[i].OauthStr = randstr.Hex(16)

		// initialize the code verifier for pkce
		codeVerif, err := cv.CreateCodeVerifier()
		if err != nil {
			log.Fatalf("failed to initialize code verifier: %v", err.Error())
		}
		conf.Applications[i].CodeVerif = codeVerif.String()

		// Create code_challenge with S256 method
		conf.Applications[i].CodeChallenge = codeVerif.CodeChallengeS256()

		faURL, err := url.Parse(app.FusionAuthHost)
		if err != nil {
			log.Fatalf("failed to parse fusionauth url: %v", err.Error())
		}

		// http client with custom options for usage with fusionauth
		hc := &http.Client{
			Timeout: time.Second * 10,
		}

		// get the fusionauth client
		conf.Applications[i].FusionAuthClient = fusionauth.NewClient(
			hc,
			faURL,
			app.FusionAuthAPIKey,
		)

		// build out the oauth2 config
		conf.Applications[i].OauthConfig = &oauth2.Config{
			RedirectURL:  app.FusionAuthOauthRedirectURL,
			ClientID:     app.FusionAuthOauthClientID,
			ClientSecret: app.FusionAuthOauthClientSecret,
			Scopes:       []string{"openid"},
			Endpoint: oauth2.Endpoint{
				AuthURL:   fmt.Sprintf("%v/oauth2/authorize", app.FusionAuthPublicHost),
				TokenURL:  fmt.Sprintf("%v/oauth2/token", app.FusionAuthPublicHost),
				AuthStyle: oauth2.AuthStyleInHeader,
			},
		}

		conf.Applications[i].AuthCodeURL = conf.Applications[i].OauthConfig.AuthCodeURL(
			conf.Applications[i].OauthStr,
			oauth2.SetAuthURLParam("response_type", "code"),
			oauth2.SetAuthURLParam("code_challenge", conf.Applications[i].CodeChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		)
	}

	// start up the api server
	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {
		log.Printf("host: %v", c.Request.Host)
		log.Printf("remoteaddr: %v", c.Request.RemoteAddr)
		log.Printf("referer: %v", c.Request.Referer())
		app, ok := conf.GetConfigForDomain(c.Request.Host)
		if !ok {
			c.Data(404, "text/plain", []byte("not found"))
		}
		log.Printf("matched app id: %v", app.FusionAuthAppID)
		c.JSON(200, gin.H{"message": "pong"})
	})
	r.GET("/pages/makepayment", func(c *gin.Context) {
		htmlstr, err := htmltemplates.GetPaymentTemplate()
		if err != nil {
			log.Printf("error getting template: %v", err.Error())
			c.Data(500, "text/plain", []byte("server error"))
			return
		}
		c.Data(200, "text/html", []byte(htmlstr))
	})
	r.GET("/auth/login", func(c *gin.Context) {
		app, ok := conf.GetConfigForDomain(c.Request.Host)
		if !ok {
			c.Data(404, "text/plain", []byte("not found"))
		}
		c.Redirect(301, app.AuthCodeURL)
	})
	r.GET("/api/currentuser/email", func(c *gin.Context) {
		app, ok := conf.GetConfigForDomain(c.Request.Host)
		if !ok {
			c.Data(404, "text/plain", []byte("not found"))
		}
		routes.GetAPICurrentUserEmail(c, app, app.FusionAuthClient)
	})
	r.GET("/pages/welcome", func(c *gin.Context) {
		app, ok := conf.GetConfigForDomain(c.Request.Host)
		if !ok {
			c.Data(404, "text/plain", []byte("not found"))
		}
		routes.LoggedIn(c, app, app.FusionAuthClient)
	})
	r.POST("/api/mutate", func(c *gin.Context) {
		routes.PostMutation(c, conf)
	})
	r.GET("/auth/oauth-cb", func(c *gin.Context) {
		app, ok := conf.GetConfigForDomain(c.Request.Host)
		if !ok {
			c.Data(404, "text/plain", []byte("not found"))
		}
		routes.OauthCallback(c, app, app.FusionAuthClient, app.CodeVerif)
	})
	err = r.Run(
		fmt.Sprintf(
			"%v:%v",
			conf.Global.BindAddr,
			conf.Global.BindPort,
		),
	)
	if err != nil {
		log.Fatalf("error running gin: %v", err.Error())
	}
}
