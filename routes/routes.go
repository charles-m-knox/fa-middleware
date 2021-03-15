package routes

import (
	"fa-middleware/auth"
	"fa-middleware/config"
	"fa-middleware/htmltemplates"
	"fa-middleware/models"
	"fa-middleware/payments"
	"fa-middleware/userdata"

	"fmt"
	"net/http"
	"time"

	"log"

	"github.com/FusionAuth/go-client/pkg/fusionauth"
	"github.com/gin-gonic/gin"
)

// GetUserFromGin extracts the user via the JWT HttpOnly cookie and will
// set the gin response if there's an error
func GetUserFromGin(c *gin.Context, conf config.Config) (user fusionauth.User, err error) {
	cookies := c.Request.Cookies()
	jwt := ""
	for _, cookie := range cookies {
		if cookie.Name == conf.JWTCookieName {
			jwt = cookie.Value
			break
		}
	}

	if jwt == "" {
		c.Data(403, "text/plain", []byte("unauthorized"))
		return user, fmt.Errorf("unauthorized")
	}

	// check if the user has a valid jwt
	user, err = auth.GetUserByJWT(conf, jwt)
	if err != nil {
		c.Data(403, "text/plain", []byte("unauthorized"))
		return user, fmt.Errorf("unauthorized")
	}

	return user, nil
}

func LoggedIn(c *gin.Context, conf config.Config, fa *fusionauth.FusionAuthClient) {
	cookies := c.Request.Cookies()
	jwt := ""
	for _, cookie := range cookies {
		if cookie.Name == conf.JWTCookieName {
			jwt = cookie.Value
			break
		}
	}

	if jwt == "" {
		c.Data(403, "text/plain", []byte("unauthorized"))
		return
	}

	// check if the user has a valid jwt
	user, err := auth.GetUserByJWT(conf, jwt)
	if err != nil {
		c.Data(403, "text/plain", []byte("unauthorized"))
		return
	}

	// render the loggedin.html template
	htmlstr, err := htmltemplates.GetLoggedInTemplate(user)
	if err != nil {
		log.Printf("error getting template: %v", err.Error())
		c.Data(500, "text/plain", []byte("server error!"))
		return
	}
	c.Data(200, "text/html", []byte(htmlstr))
}

func OauthCallback(c *gin.Context, conf config.Config, fa *fusionauth.FusionAuthClient, codeVerif string) {
	// https://github.com/gin-gonic/examples/blob/master/basic/main.go
	err := c.Request.ParseForm()
	if err != nil {
		log.Printf("oauth-callback failed to process form: %v", err.Error())
		c.Data(403, "text/plain", []byte("unauthorized"))
		return
	}

	receivedOauthState, ok := c.Request.Form["state"]
	if !ok {
		log.Printf("login: no state")
		c.Data(403, "text/plain", []byte("unauthorized"))
		return
	}
	receivedOauthCode, ok := c.Request.Form["code"]
	if !ok {
		log.Printf("login: no code")
		c.Data(403, "text/plain", []byte("unauthorized"))
		return
	}

	if len(receivedOauthState) != 1 || len(receivedOauthCode) != 1 {
		log.Printf("login: didn't receive 1 state and 1 code")
		c.Data(403, "text/plain", []byte("unauthorized"))
		return
	}

	oauths := models.OauthState{
		Code:     receivedOauthCode[0],
		State:    receivedOauthState[0],
		Verifier: codeVerif,
	}

	// log.Printf("post form array: %v", c.Request.Form)

	user, jwt, err := auth.Login(conf, fa, oauths)
	if err != nil {
		log.Printf("err login: %v", err.Error())
		c.Data(403, "text/plain", []byte("unauthorized"))
		return
	}

	err = userdata.SetUserData(
		conf,
		models.UserData{
			UserID:    user.Id,
			TenantID:  conf.FusionAuthTenantID,
			AppID:     conf.FusionAuthAppID,
			Field:     "login",
			Value:     "1",
			UpdatedAt: time.Now().UnixNano() / 1000000,
		},
	)

	if err != nil {
		log.Printf("error setting user data: %v", err.Error())
		c.Data(500, "text/plain", []byte("server error"))
		return
	}

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(
		conf.JWTCookieName,
		jwt,
		conf.JWTCookieMaxAgeSeconds, // TODO: change this to a bigger value than 1 hour?
		"/",
		conf.JWTCookieDomain,    // TODO: integrate with multi-tenancy?
		conf.JWTCookieSetSecure, // TODO: use secure only
		true,
	)

	_, err = payments.PropagateUserToStripe(conf, user)
	if err != nil {
		log.Printf(
			"failed to push user %v to stripe: %v",
			user.Id,
			err.Error(),
		)
		c.Redirect(301, "/pages/welcome")
		return
	}

	c.Redirect(301, "/pages/welcome")
}

func GetAuthLogout(c *gin.Context, conf config.Config, fa *fusionauth.FusionAuthClient) {
	cookies := c.Request.Cookies()
	jwt := ""
	for _, cookie := range cookies {
		if cookie.Name == conf.JWTCookieName {
			jwt = cookie.Value
			break
		}
	}

	if jwt == "" {
		c.Data(403, "text/plain", []byte("unauthorized"))
		return
	}

	// get the current user
	u, errs, err := fa.RetrieveUserUsingJWT(jwt)
	if err != nil {
		log.Printf("currentuser/email: %v", err.Error())
		c.Data(403, "text/plain", []byte("unauthorized"))
		return
	}
	if errs != nil {
		c.Data(403, "text/plain", []byte("unauthorized"))
		return
	}

	c.Data(200, "text/plain", []byte(u.User.Email))
}

func GetAPICurrentUserEmail(c *gin.Context, conf config.Config, fa *fusionauth.FusionAuthClient) {
	cookies := c.Request.Cookies()
	jwt := ""
	for _, cookie := range cookies {
		if cookie.Name == conf.JWTCookieName {
			jwt = cookie.Value
			break
		}
	}

	if jwt == "" {
		c.Data(403, "text/plain", []byte("unauthorized"))
		return
	}

	// get the current user
	u, errs, err := fa.RetrieveUserUsingJWT(jwt)
	if err != nil {
		log.Printf("currentuser/email: %v", err.Error())
		c.Data(403, "text/plain", []byte("unauthorized"))
		return
	}
	if errs != nil {
		c.Data(403, "text/plain", []byte("unauthorized"))
		return
	}

	c.Data(200, "text/plain", []byte(u.User.Email))
}

// PostMutation allows an external api to arbitrarily mutate
// user data in the postgresdb for a user, assuming they are authorized.
// requires a few things:
// - a jwt for the user
// - the name of the field to modify in the db
// - the value of the corresponding field to set in the db
func PostMutation(c *gin.Context, conf config.CompleteConfig) {
	var mutation models.PostMutationBody
	err := c.Bind(&mutation)
	if err != nil ||
		mutation.Field == "" ||
		mutation.Method == "" {
		c.Data(400, "text/plain", []byte("bad request"))
		return
	}

	// allows for requests to come from either this API directly
	// or from some other service
	// TODO: allow for a passlist of c.Request.Host values so that requests
	// can only come from other approved locations
	app, ok := conf.GetConfigForDomain(c.Request.Host)
	if !ok {
		log.Printf(
			"post mutation: didn't find domain %v, trying mutation body",
			c.Request.Host,
		)
		app, ok = conf.GetConfigForDomain(mutation.Domain)
		if !ok {
			c.Data(404, "text/plain", []byte("not found"))
			return
		}
	}

	// need to extract the HttpOnly cookie because it won't be included in the request
	cookies := c.Request.Cookies()
	mutation.JWT = ""
	for _, cookie := range cookies {
		if cookie.Name == app.JWTCookieName {
			mutation.JWT = cookie.Value
			break
		}
	}

	if mutation.JWT == "" {
		c.Data(403, "text/plain", []byte("unauthorized"))
		return
	}

	// talk to fusionauth to validate the jwt
	user, err := auth.GetUserByJWT(app, mutation.JWT)
	if err != nil {
		c.Data(403, "text/plain", []byte("unauthorized"))
		return
	}

	// validate that the user's tenant id matches this app's tenant id
	if user.TenantId != app.FusionAuthTenantID {
		log.Printf(
			"post mutation: user tenant id %v did not match app tenant id %v",
			user.TenantId,
			app.FusionAuthTenantID,
		)
		c.Data(403, "text/plain", []byte("unauthorized"))
		return
	}

	userData := models.UserData{
		UserID:   user.Id,
		AppID:    app.FusionAuthAppID,
		TenantID: user.TenantId,
		Field:    mutation.Field,
		Value:    mutation.Value,
	}

	// check that the method is valid now, before checking if it's mutable,
	// because the mutability check performs an API call to Stripe in some cases
	// and can take time
	if mutation.Method != "g" && mutation.Method != "s" {
		c.Data(400, "text/plain", []byte("bad request"))
		return
	}

	mutable, err := payments.IsFieldMutable(app, mutation)
	if err != nil {
		log.Printf(
			"failed to check mutability for user id %v, field %v: %v",
			user.Id,
			mutation.Field,
			err.Error(),
		)
		c.Data(500, "text/plain", []byte("server error"))
		return
	}

	if !mutable {
		c.Data(403, "text/plain", []byte("forbidden"))
		return
	}

	switch mutation.Method {
	case "g":
		if userData.Value != "" {
			log.Printf("post mutate get user data: value %v should be empty", userData.Value)
			c.Data(400, "text/plain", []byte("bad request"))
			return
		}
		// get the data via postgres
		// err = userdata.GetUserData(app, &userData)
		value, err := userdata.GetValueForUser(app, user, mutation.Field)
		if err != nil {
			log.Printf("failed to write user data on mutation: %v", err.Error())
			c.Data(500, "text/plain", []byte("server error"))
			return
		}
		c.Data(200, "text/plain", []byte(value))
		return
	case "s":
		// https://gobyexample.com/epoch
		userData.UpdatedAt = time.Now().UnixNano() / 1000000
		// write the data via postgres
		// err = userdata.SetUserData(app, userData)
		err := userdata.SetValueForUser(app, user, mutation.Field, mutation.Value)
		if err != nil {
			log.Printf("failed to write user data on mutation: %v", err.Error())
			c.Data(500, "text/plain", []byte("server error"))
			return
		}
		c.Data(200, "text/plain", []byte(fmt.Sprintf("%v", userData.UpdatedAt)))
		return
	}

	c.Data(400, "text/plain", []byte("bad request"))
}

/*
func GetUserData(c *gin.Context, conf config.CompleteConfig, field string) {
	field, ok := c.Params.Get("f")
	if !ok {
		c.Data(400, "text/plain", []byte("bad request"))
		return
	}

	// allows for requests to come from either this API directly
	// or from some other service
	// TODO: allow for a passlist of c.Request.Host values so that requests
	// can only come from other approved locations
	app, ok := conf.GetConfigForDomain(c.Request.Host)
	if !ok {
		log.Printf(
			"post mutation: didn't find domain %v, trying mutation body",
			c.Request.Host,
		)
		// app, ok = conf.GetConfigForDomain(mutation.Domain)
		// if !ok {
		// 	c.Data(404, "text/plain", []byte("not found"))
		// 	return
		// }
	}

	// talk to fusionauth to validate the jwt
	user, err := auth.GetUserByJWT(app, mutation.JWT)
	if err != nil {
		c.Data(403, "text/plain", []byte("unauthorized"))
		return
	}

	// validate that the user's tenant id matches this app's tenant id
	if user.TenantId != app.FusionAuthTenantID {
		log.Printf(
			"post mutation: user tenant id %v did not match app tenant id %v",
			user.TenantId,
			app.FusionAuthTenantID,
		)
		c.Data(403, "text/plain", []byte("unauthorized"))
		return
	}

	userData := models.UserData{
		UserID:   user.Id,
		AppID:    app.FusionAuthAppID,
		TenantID: user.TenantId,
		Field:    mutation.Field,
	}

	// get the data via postgres
	err = userdata.GetUserData(app, &userData)
	if err != nil {
		log.Printf("failed to get user data for field: %v", err.Error())
		c.Data(500, "text/plain", []byte("server error"))
	}

	c.Data(200, "text/plain", []byte(userData.Value))
}
*/
