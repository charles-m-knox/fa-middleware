package main

import (
	"fa-middleware/auth"
	"fa-middleware/config"
	h "fa-middleware/helpers"
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
	payments.InitializeSubscribedUserCache()

	conf, err := config.LoadConfigYaml()
	if err != nil {
		log.Fatalf("failed to load config2: %v", err.Error())
	}

	for i, app := range conf.Apps {
		// initialize oauth state
		conf.Apps[i].Oauth2Config.OauthStr = randstr.Hex(16)

		// initialize the code verifier for pkce
		codeVerif, err := cv.CreateCodeVerifier()
		if err != nil {
			log.Fatalf("failed to initialize code verifier: %v", err.Error())
		}
		conf.Apps[i].Oauth2Config.CodeVerif = codeVerif.String()

		// Create code_challenge with S256 method
		conf.Apps[i].Oauth2Config.CodeChallenge = codeVerif.CodeChallengeS256()

		faURL, err := url.Parse(app.FusionAuth.InternalHostURL)
		if err != nil {
			log.Fatalf("failed to parse fusionauth url: %v", err.Error())
		}

		// http client with custom options for usage with fusionauth
		hc := &http.Client{Timeout: time.Second * 10}

		// get the fusionauth client
		conf.Apps[i].FusionAuth.Client = fusionauth.NewClient(
			hc,
			faURL,
			app.FusionAuth.APIKey,
		)

		// build out the oauth2 config
		conf.Apps[i].Oauth2Config.OauthConfig = &oauth2.Config{
			RedirectURL:  auth.GetOauthRedirectURL(app),
			ClientID:     app.FusionAuth.OauthClientID,
			ClientSecret: app.FusionAuth.OauthClientSecret,
			Scopes:       []string{"openid"},
			Endpoint: oauth2.Endpoint{
				AuthURL:   fmt.Sprintf("%v/oauth2/authorize", app.FusionAuth.PublicHostURL),
				TokenURL:  fmt.Sprintf("%v/oauth2/token", app.FusionAuth.PublicHostURL),
				AuthStyle: oauth2.AuthStyleInHeader,
			},
		}

		conf.Apps[i].Oauth2Config.AuthCodeURL = conf.Apps[i].Oauth2Config.OauthConfig.AuthCodeURL(
			conf.Apps[i].Oauth2Config.OauthStr,
			oauth2.SetAuthURLParam("response_type", "code"),
			oauth2.SetAuthURLParam("code_challenge", conf.Apps[i].Oauth2Config.CodeChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		)
	}

	// start up the api server
	r := gin.Default()
	r.GET("/mw/ping", func(c *gin.Context) {
		_, ok := routes.GetConfigViaRouteOrigin(c, conf)
		if !ok {
			h.Simple404(c)
			return
		}
		c.JSON(200, gin.H{"message": "pong"})
	})
	r.OPTIONS("/mw/create-checkout-session", func(c *gin.Context) {
		_, ok := routes.GetConfigViaRouteOrigin(c, conf)
		if !ok {
			h.Simple404(c)
			return
		}
		h.SetCORSMethods(c)
		h.Simple200OK(c)
	})
	r.POST("/mw/create-checkout-session", func(c *gin.Context) {
		app, ok := routes.GetConfigViaRouteOrigin(c, conf)
		if !ok {
			h.Simple404(c)
			return
		}

		user, err := routes.GetUserFromGin(c, app)
		if err != nil {
			return
		}

		h.SetCORSMethods(c)

		err = payments.CreateCheckoutSession(c, app, user)
		if err != nil {
			log.Printf(
				"failed to create checkout session for user %v: %v",
				user.Id,
				err.Error(),
			)
			h.Simple500(c)
			return
		}
	})
	r.OPTIONS("/mw/substatus", func(c *gin.Context) {
		_, ok := routes.GetConfigViaRouteOrigin(c, conf)
		if !ok {
			h.Simple404(c)
			return
		}
		h.Simple200OK(c)
	})
	r.GET("/mw/substatus", func(c *gin.Context) {
		// alllows a logged-in user to check to see if they are subscribed
		// to a product
		app, ok := routes.GetConfigViaRouteOrigin(c, conf)
		if !ok {
			h.Simple404(c)
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
				app.FusionAuth.AppID,
				user.Id,
				productID,
				err.Error(),
			)
			h.Simple500(c)
			return
		}
		c.Data(200, "text/plain", []byte(fmt.Sprintf("%v", subscribed)))
	})
	r.OPTIONS("/mw/private/substatus", func(c *gin.Context) {
		h.Simple200OK(c)
	})
	r.POST("/mw/private/substatus", func(c *gin.Context) {
		// enables other api's to check if a user is subscribed
		sBody := models.SubscriptionStatusCheckBody{} // "value" will hold the product id
		err := c.Bind(&sBody)
		if err != nil {
			h.Simple404(c)
			return
		}

		if sBody.APIKey == "" {
			c.Data(401, "text/plain", []byte("unauthorized"))
			return
		}

		for _, app := range conf.Apps {
			if sBody.APIKey == app.APIKey {
				user := fusionauth.User{}
				// if the jwt isn't specified, attempt to retrieve the user via the other params
				if sBody.JWT == "" {
					if sBody.UserID == "" {
						c.Data(400, "text/plain", []byte("not all required fields were specified for substatus"))
						return
					}
					// TODO: properly handler the "errors" return value
					qUser, _, err := app.FusionAuth.Client.RetrieveUser(sBody.UserID)
					if err != nil {
						log.Printf("failed to find user for substatus: %v", err.Error())
						c.Data(400, "text/plain", []byte("failed to find user"))
						return
					}
					if qUser.User.Id != sBody.UserID {
						c.Data(400, "text/plain", []byte("failed to find user"))
						return
					}
					// if errs.Present() {
					// 	log.Printf("errs finding user for substatus: %v", errs)
					// 	c.Data(400, "text/plain", []byte("failed to find user"))
					// 	return
					// }
					user = qUser.User
				}

				if user.Id == "" {
					qUser, err := auth.GetUserByJWT(app, sBody.JWT)
					if err != nil {
						c.Data(400, "text/plain", []byte("jwt doesn't correspond to any user"))
						return
					}
					user = qUser
				}

				// check if the user is subscribed now
				result, err := payments.IsUserSubscribed(app, user, sBody.ProductID)
				if err != nil {
					log.Printf(
						"failed to check if user is subscribed to product %v: %v",
						sBody.ProductID,
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
			h.Simple404(c)
			return
		}
		h.Simple200OK(c)
	})
	r.GET("/mw/login", func(c *gin.Context) {
		app, ok := routes.GetConfigViaRouteOrigin(c, conf)
		if !ok {
			h.Simple404(c)
			return
		}
		// check if the user is already logged in
		jwt := routes.GetJWTFromGin(c, app)
		if jwt != "" {
			log.Printf("user is already logged in")
			user, err := auth.GetUserByJWT(app, jwt)
			if err != nil {
				log.Printf("user is already logged in, failed to get user: %v", err.Error())
				c.Redirect(301, app.Oauth2Config.AuthCodeURL)
				return
			}

			if user.Id != "" {
				c.Data(200, "text/plain", []byte("already logged in"))
				return
			}
		}
		// user is not logged in, so redirect
		c.Redirect(301, app.Oauth2Config.AuthCodeURL)
	})
	r.OPTIONS("/mw/loggedin", func(c *gin.Context) {
		_, ok := routes.GetConfigViaRouteOrigin(c, conf)
		if !ok {
			h.Simple404(c)
			return
		}
		h.Simple200OK(c)
	})
	r.GET("/mw/loggedin", func(c *gin.Context) {
		app, ok := routes.GetConfigViaRouteOrigin(c, conf)
		if !ok {
			h.Simple404(c)
			return
		}
		routes.LoggedIn(c, app, app.FusionAuth.Client)
	})
	r.OPTIONS("/mw/products", func(c *gin.Context) {
		_, ok := routes.GetConfigViaRouteOrigin(c, conf)
		if !ok {
			h.Simple404(c)
			return
		}
		h.Simple200OK(c)
	})
	r.GET("/mw/products", func(c *gin.Context) {
		app, ok := routes.GetConfigViaRouteOrigin(c, conf)
		if !ok {
			h.Simple404(c)
			return
		}
		products, err := payments.GetProducts(app)
		if err != nil {
			log.Printf("/mw/products failure: %v", err.Error())
			h.Simple500(c)
			return
		}
		c.JSON(200, products)
	})
	r.GET("/mw/oauth-cb/:appId", func(c *gin.Context) {
		appID := c.Params.ByName("appId")
		if appID == "" {
			h.Simple404(c)
			return
		}
		app, ok := conf.GetConfigForAppID(appID)
		if !ok {
			h.Simple404(c)
			return
		}
		// app, ok := conf.GetConfigForDomain(c.Request.Host)
		// if !ok {
		// 	h.Simple404(c)
		// 	return
		// }
		routes.OauthCallback(c, app, app.FusionAuth.Client)
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
