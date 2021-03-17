package routes

import (
	"fa-middleware/auth"
	"fa-middleware/config"
	"fa-middleware/models"
	"fa-middleware/payments"

	"fmt"
	"net/http"
	"net/url"

	"log"

	"github.com/FusionAuth/go-client/pkg/fusionauth"
	"github.com/gin-gonic/gin"
)

// GetConfigViaRouteOrigin sets the CORS headers that will allow HttpOnly
// cookies to work when requests are made via the web browser, as well as
// automatically retrieving the app config that corresponds to the request
// origin
func GetConfigViaRouteOrigin(c *gin.Context, conf config.Config) (app config.App, success bool) {
	originHeader := c.Request.Header.Get("Origin")
	if originHeader == "" {
		referer := c.Request.Header.Get("Referer")
		if referer == "" {
			c.Data(404, "text/plain", []byte("not found"))
			return
		}
		originHeader = referer
	}
	parsedURL, err := url.Parse(originHeader)
	if err != nil {
		c.Data(404, "text/plain", []byte("not found"))
		return
	}
	origin := parsedURL.Host
	log.Printf("origin: %v", origin)
	app, ok := conf.GetAppByOrigin(origin)
	if !ok {
		return app, false
	}
	c.Header("Access-Control-Allow-Origin", app.FullDomainURL)
	c.Header("Access-Control-Allow-Credentials", "true")
	return app, true
}

// GetUserFromGin extracts the user via the JWT HttpOnly cookie and will
// set the gin response if there's an error
func GetUserFromGin(c *gin.Context, app config.App) (user fusionauth.User, err error) {
	cookies := c.Request.Cookies()
	jwt := ""
	for _, cookie := range cookies {
		if cookie.Name == app.JWT.CookieName {
			jwt = cookie.Value
			break
		}
	}

	if jwt == "" {
		c.Data(403, "text/plain", []byte("unauthorized"))
		return user, fmt.Errorf("unauthorized")
	}

	// check if the user has a valid jwt
	user, err = auth.GetUserByJWT(app, jwt)
	if err != nil {
		c.Data(403, "text/plain", []byte("unauthorized"))
		return user, fmt.Errorf("unauthorized")
	}

	return user, nil
}

// GetJWTFromGin allows for quick retrieval of a JWT HttpOnly cookie from
// a Gin context
func GetJWTFromGin(c *gin.Context, app config.App) string {
	cookies := c.Request.Cookies()
	for _, cookie := range cookies {
		if cookie.Name == app.JWT.CookieName {
			return cookie.Value
		}
	}
	return ""
}

// LoggedIn allows the frontend to quickly check if the user is logged in
func LoggedIn(c *gin.Context, app config.App, fa *fusionauth.FusionAuthClient) {
	jwt := GetJWTFromGin(c, app)
	resp := models.LoggedInResponse{}

	if jwt == "" {
		log.Printf("loggedin: empty jwt")
		c.JSON(200, resp)
		return
	}

	// check if the user has a valid jwt
	user, err := auth.GetUserByJWT(app, jwt)
	if err != nil {
		log.Printf("loggedin: couldn't get user")
		c.JSON(200, resp)
		return
	}

	resp.LoggedIn = true
	resp.UserID = user.Id
	resp.UserEmail = user.Email
	resp.UserFullName = user.FullName

	c.JSON(200, resp)
}

func OauthCallback(c *gin.Context, app config.App, fa *fusionauth.FusionAuthClient) {
	err := c.Request.ParseForm()
	if err != nil {
		log.Printf("oauth-callback failed to process form: %v", err.Error())
		c.Data(403, "text/plain", []byte("unauthorized"))
		return
	}

	oastate, ok := c.Request.Form["state"]
	if !ok {
		log.Printf("login: no state")
		c.Data(403, "text/plain", []byte("unauthorized"))
		return
	}
	oacode, ok := c.Request.Form["code"]
	if !ok {
		log.Printf("login: no code")
		c.Data(403, "text/plain", []byte("unauthorized"))
		return
	}

	if len(oastate) != 1 || len(oacode) != 1 {
		log.Printf("login: didn't receive 1 state and 1 code")
		c.Data(403, "text/plain", []byte("unauthorized"))
		return
	}

	oauths := models.OauthState{
		Code:     oacode[0],
		State:    oastate[0],
		Verifier: app.Oauth2Config.CodeVerif,
	}

	user, jwt, err := auth.Login(app, fa, oauths)
	if err != nil {
		log.Printf("err login: %v", err.Error())
		c.Data(403, "text/plain", []byte("unauthorized"))
		return
	}

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(
		app.JWT.CookieName,
		jwt,
		app.JWT.CookieMaxAgeSeconds,
		"/",
		app.JWT.CookieDomain,
		app.JWT.CookieSetSecure,
		true,
	)

	_, err = payments.PropagateUserToStripe(app, user)
	if err != nil {
		log.Printf(
			"failed to push user %v to stripe: %v",
			user.Id,
			err.Error(),
		)
		c.Redirect(301, app.FusionAuth.AuthCallbackRedirectURL)
		return
	}

	c.Redirect(301, app.FusionAuth.AuthCallbackRedirectURL)
}
