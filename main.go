package main

import (
	"fa-middleware/auth"
	"fa-middleware/config"
	"fa-middleware/models"
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

	payments.InitializeSubscribedUserCache()

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
	r.GET("/mw/ping", func(c *gin.Context) {
		_, ok := routes.GetConfigViaRouteOrigin(c, conf)
		if !ok {
			c.Data(404, "text/plain", []byte("not found"))
			return
		}
		c.JSON(200, gin.H{"message": "pong"})
	})
	r.OPTIONS("/mw/create-checkout-session", func(c *gin.Context) {
		_, ok := routes.GetConfigViaRouteOrigin(c, conf)
		if !ok {
			c.Data(404, "text/plain", []byte("not found"))
			return
		}
		c.Header("Access-Control-Allow-Methods", "OPTIONS, POST")
		c.Data(200, "text/plain", []byte("OK"))
	})
	r.POST("/mw/create-checkout-session", func(c *gin.Context) {
		app, ok := routes.GetConfigViaRouteOrigin(c, conf)
		if !ok {
			c.Data(404, "text/plain", []byte("not found"))
			return
		}
		user, err := routes.GetUserFromGin(c, app) // will set the gin response if there's an error
		if err != nil {
			return
		}
		c.Header("Access-Control-Allow-Methods", "OPTIONS, POST")
		err = payments.CreateCheckoutSession(c, app, user) // will set the gin response unless there's an error
		if err != nil {
			log.Printf("failed to create checkout session for user %v: %v", user.Id, err.Error())
			c.Data(500, "text/plain", []byte("server error"))
			return
		}
	})
	r.OPTIONS("/mw/substatus", func(c *gin.Context) {
		_, ok := routes.GetConfigViaRouteOrigin(c, conf)
		if !ok {
			c.Data(404, "text/plain", []byte("not found"))
			return
		}
		c.Data(200, "text/plain", []byte("OK"))
	})
	r.GET("/mw/substatus", func(c *gin.Context) {
		// alllows a logged-in user to check to see if they are subscribed
		// to a product
		app, ok := routes.GetConfigViaRouteOrigin(c, conf)
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
	r.OPTIONS("/mw/private/substatus", func(c *gin.Context) {
		c.Data(200, "text/plain", []byte("OK"))
	})
	r.POST("/mw/private/substatus", func(c *gin.Context) {
		// enables other api's to check if a user is subscribed
		postMutationBody := models.PostMutationBody{} // "value" will hold the product id
		err := c.Bind(&postMutationBody)
		if err != nil {
			c.Data(404, "text/plain", []byte("not found"))
			return
		}
		if postMutationBody.JWT == "" ||
			postMutationBody.Key == "" ||
			postMutationBody.Domain == "" ||
			postMutationBody.Value == "" {
			c.Data(400, "text/plain", []byte("not all required fields were specified for substatus"))
			return
		}
		for _, app := range conf.Applications {
			if postMutationBody.Domain == app.Domain && postMutationBody.Key == app.MutationKey {
				// get the jwt now
				user, err := auth.GetUserByJWT(app, postMutationBody.JWT)
				if err != nil {
					c.Data(400, "text/plain", []byte("jwt doesn't correspond to any user"))
					return
				}

				// check if the user is subscribed now
				result, err := payments.IsUserSubscribed(app, user, postMutationBody.Value)
				if err != nil {
					log.Printf(
						"failed to check if user is subscribed to product %v: %v",
						postMutationBody.Value,
						err.Error(),
					)
					c.Data(400, "text/plain", []byte("failed to check if user is subscribed"))
					return
				}
				c.Data(200, "text/plain", []byte(fmt.Sprintf("%v", result)))
				return
			}
		}
		c.Data(401, "text/plain", []byte("unauthorized"))
	})
	r.OPTIONS("/mw/login", func(c *gin.Context) {
		_, ok := routes.GetConfigViaRouteOrigin(c, conf)
		if !ok {
			c.Data(404, "text/plain", []byte("not found"))
			return
		}
		c.Data(200, "text/plain", []byte("OK"))
	})
	r.GET("/mw/login", func(c *gin.Context) {
		app, ok := routes.GetConfigViaRouteOrigin(c, conf)
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
	r.OPTIONS("/mw/loggedin", func(c *gin.Context) {
		_, ok := routes.GetConfigViaRouteOrigin(c, conf)
		if !ok {
			c.Data(404, "text/plain", []byte("not found"))
			return
		}
		c.Data(200, "text/plain", []byte("OK"))
	})
	r.GET("/mw/loggedin", func(c *gin.Context) {
		app, ok := routes.GetConfigViaRouteOrigin(c, conf)
		if !ok {
			c.Data(404, "text/plain", []byte("not found"))
			return
		}
		routes.LoggedIn(c, app, app.FusionAuthClient)
	})
	r.OPTIONS("/mw/mutate", func(c *gin.Context) {
		_, ok := routes.GetConfigViaRouteOrigin(c, conf)
		if !ok {
			c.Data(404, "text/plain", []byte("not found"))
			return
		}
		c.Header("Access-Control-Allow-Methods", "OPTIONS, POST")
		c.Header("Access-Control-Allow-Headers", "X-PINGOTHER, content-type")
		c.Data(200, "text/plain", []byte("OK"))
	})
	r.POST("/mw/mutate", func(c *gin.Context) {
		_, ok := routes.GetConfigViaRouteOrigin(c, conf)
		if !ok {
			c.Data(404, "text/plain", []byte("not found"))
			return
		}
		c.Header("Access-Control-Allow-Methods", "OPTIONS, POST")
		c.Header("Access-Control-Allow-Headers", "X-PINGOTHER, content-type")
		routes.PostMutation(c, conf)
	})
	r.OPTIONS("/mw/products", func(c *gin.Context) {
		_, ok := routes.GetConfigViaRouteOrigin(c, conf)
		if !ok {
			c.Data(404, "text/plain", []byte("not found"))
			return
		}
		c.Data(200, "text/plain", []byte("OK"))
	})
	r.GET("/mw/products", func(c *gin.Context) {
		app, ok := routes.GetConfigViaRouteOrigin(c, conf)
		if !ok {
			c.Data(404, "text/plain", []byte("not found"))
			return
		}
		products, err := payments.GetProducts(app)
		if err != nil {
			log.Printf("/mw/products failure: %v", err.Error())
			c.Data(500, "text/plain", []byte("server error"))
			return
		}
		c.JSON(200, products)
	})
	r.GET("/mw/oauth-cb/:appId", func(c *gin.Context) {
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
