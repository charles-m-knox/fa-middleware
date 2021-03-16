package main

import (
	"fa-middleware/auth"
	"fa-middleware/config"
	"fa-middleware/htmltemplates"
	"fa-middleware/payments"
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
			RedirectURL:  auth.GetOauthRedirectURL(app),
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
		_, _, ok := routes.GetConfigViaRouteOrigin(c, conf)
		if !ok {
			c.Data(404, "text/plain", []byte("not found"))
			return
		}
		c.JSON(200, gin.H{"message": "pong"})
	})
	r.GET("/assets/:file", func(c *gin.Context) {
		fileName, ok := c.Params.Get("file")
		log.Printf("/assets/t/: %v", fileName)
		if !ok {
			c.Data(404, "text/plain", []byte("not found"))
			return
		}
		c.File(fmt.Sprintf("assets/%v", fileName))
	})
	r.GET("/pages/t/:file", func(c *gin.Context) {
		fileName, ok := c.Params.Get("file")
		if !ok {
			c.Data(404, "text/plain", []byte("not found"))
			return
		}
		app, ok := conf.GetConfigForDomain(c.Request.Host)
		if !ok {
			c.Data(404, "text/plain", []byte("not found"))
			return
		}
		user, err := routes.GetUserFromGin(c, app) // will set the gin response if there's an error
		if err != nil {
			return
		}
		htmlstr, err := htmltemplates.GetTemplateByName(app, user, fileName)
		if err != nil {
			log.Printf("template failure for file %v: %v", fileName, err.Error())
			c.Data(404, "text/plain", []byte("not found"))
			return
		}
		c.Data(200, "text/html", []byte(htmlstr))
	})
	r.OPTIONS("/api/create-checkout-session", func(c *gin.Context) {
		_, _, ok := routes.GetConfigViaRouteOrigin(c, conf)
		if !ok {
			c.Data(404, "text/plain", []byte("not found"))
			return
		}
		c.Data(200, "text/plain", []byte("OK"))
	})
	r.POST("/api/create-checkout-session", func(c *gin.Context) {
		app, _, ok := routes.GetConfigViaRouteOrigin(c, conf)
		if !ok {
			c.Data(404, "text/plain", []byte("not found"))
			return
		}
		user, err := routes.GetUserFromGin(c, app) // will set the gin response if there's an error
		if err != nil {
			return
		}
		err = payments.CreateCheckoutSession(c, app) // will set the gin response unless there's an error
		if err != nil {
			log.Printf("failed to create checkout session for user %v: %v", user.Id, err.Error())
			c.Data(500, "text/plain", []byte("server error"))
			return
		}
	})
	r.OPTIONS("/auth/substatus", func(c *gin.Context) {
		_, _, ok := routes.GetConfigViaRouteOrigin(c, conf)
		if !ok {
			c.Data(404, "text/plain", []byte("not found"))
			return
		}
		c.Data(200, "text/plain", []byte("OK"))
	})
	r.GET("/api/substatus", func(c *gin.Context) {
		app, _, ok := routes.GetConfigViaRouteOrigin(c, conf)
		if !ok {
			c.Data(404, "text/plain", []byte("not found"))
			return
		}
		user, err := routes.GetUserFromGin(c, app) // will set the gin response if there's an error
		if err != nil {
			return
		}
		productID := c.Query("p")
		if productID == "" { // TODO: add validation that this app contains this product ID
			c.Data(400, "text/plain", []byte("invalid p value"))
			return
		}
		subscribed, err := payments.IsUserSubscribed(app, user, productID)
		if err != nil {
			log.Printf(
				"failed to check app id %v if user id %v is subscribed to product ID %v: %v",
				app.FusionAuthAppID,
				user.Id,
				productID,
				err.Error(),
			)
			c.Data(500, "text/plain", []byte("server error"))
			return
		}
		c.Data(200, "text/plain", []byte(fmt.Sprintf("%v", subscribed)))
	})
	// r.GET("/pages/makepayment", func(c *gin.Context) {
	// 	app, ok := conf.GetConfigForDomain(c.Request.Host)
	// 	if !ok {
	// 		c.Data(404, "text/plain", []byte("not found"))
	// 		return
	// 	}
	// 	htmlstr, err := htmltemplates.GetPaymentTemplate(app)
	// 	if err != nil {
	// 		log.Printf("error getting template: %v", err.Error())
	// 		c.Data(500, "text/plain", []byte("server error"))
	// 		return
	// 	}
	// 	c.Data(200, "text/html", []byte(htmlstr))
	// })
	// r.GET("/pages/welcome", func(c *gin.Context) {
	// 	app, ok := conf.GetConfigForDomain(c.Request.Host)
	// 	if !ok {
	// 		c.Data(404, "text/plain", []byte("not found"))
	// 	}
	// 	routes.LoggedIn(c, app, app.FusionAuthClient)
	// })
	r.OPTIONS("/auth/login", func(c *gin.Context) {
		_, _, ok := routes.GetConfigViaRouteOrigin(c, conf)
		if !ok {
			c.Data(404, "text/plain", []byte("not found"))
			return
		}
		c.Data(200, "text/plain", []byte("OK"))
	})
	r.GET("/auth/login", func(c *gin.Context) {
		log.Printf("login: %v", c.Request.Header)
		origin := c.Request.Header.Get("Origin")
		if origin == "" {
			referer := c.Request.Header.Get("Referer")
			if referer == "" {
				c.Data(404, "text/plain", []byte("not found"))
				return
			}
			origin = referer
		}
		log.Printf("origin: %v", origin)
		app, ok := conf.GetConfigForOrigin(origin)
		if !ok {
			c.Data(404, "text/plain", []byte("not found"))
			return
		}
		// check if the user is already logged in
		jwt := routes.GetJWTFromGin(c, app)
		if jwt != "" {
			user, err := auth.GetUserByJWT(app, jwt)
			if err != nil {
				c.Redirect(301, app.AuthCodeURL)
				return
			}

			if user.Id != "" {
				c.Data(200, "text/plain", []byte("already logged in"))
				return
			}
		}
		// user is not logged in, so redirect
		c.Redirect(301, app.AuthCodeURL)
	})
	r.OPTIONS("/auth/loggedin", func(c *gin.Context) {
		_, _, ok := routes.GetConfigViaRouteOrigin(c, conf)
		if !ok {
			c.Data(404, "text/plain", []byte("not found"))
			return
		}
		c.Data(200, "text/plain", []byte("OK"))
	})
	r.GET("/auth/loggedin", func(c *gin.Context) {
		app, _, ok := routes.GetConfigViaRouteOrigin(c, conf)
		if !ok {
			c.Data(404, "text/plain", []byte("not found"))
			return
		}
		routes.LoggedIn(c, app, app.FusionAuthClient)
	})
	// r.GET("/api/currentuser/email", func(c *gin.Context) {
	// 	app, ok := conf.GetConfigForDomain(c.Request.Host)
	// 	if !ok {
	// 		c.Data(404, "text/plain", []byte("not found"))
	// 	}
	// 	routes.GetAPICurrentUserEmail(c, app, app.FusionAuthClient)
	// })
	r.OPTIONS("/api/mutate", func(c *gin.Context) {
		_, _, ok := routes.GetConfigViaRouteOrigin(c, conf)
		if !ok {
			c.Data(404, "text/plain", []byte("not found"))
			return
		}
		c.Data(200, "text/plain", []byte("OK"))
	})
	r.POST("/api/mutate", func(c *gin.Context) {
		_, _, ok := routes.GetConfigViaRouteOrigin(c, conf)
		if !ok {
			c.Data(404, "text/plain", []byte("not found"))
			return
		}
		routes.PostMutation(c, conf)
	})
	r.OPTIONS("/api/products", func(c *gin.Context) {
		_, _, ok := routes.GetConfigViaRouteOrigin(c, conf)
		if !ok {
			c.Data(404, "text/plain", []byte("not found"))
			return
		}
		c.Data(200, "text/plain", []byte("OK"))
	})
	r.GET("/api/products", func(c *gin.Context) {
		app, _, ok := routes.GetConfigViaRouteOrigin(c, conf)
		if !ok {
			c.Data(404, "text/plain", []byte("not found"))
			return
		}
		products, err := payments.GetProducts(app)
		if err != nil {
			log.Printf("/api/products failure: %v", err.Error())
			c.Data(500, "text/plain", []byte("server error"))
			return
		}
		c.JSON(200, products)
	})
	r.GET("/auth/oauth-cb/:appId", func(c *gin.Context) {
		appID := c.Params.ByName("appId")
		if appID == "" {
			c.Data(404, "text/plain", []byte("not found"))
			return
		}
		app, ok := conf.GetConfigForAppID(appID)
		if !ok {
			c.Data(404, "text/plain", []byte("not found"))
			return
		}
		// app, ok := conf.GetConfigForDomain(c.Request.Host)
		// if !ok {
		// 	c.Data(404, "text/plain", []byte("not found"))
		// 	return
		// }
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
