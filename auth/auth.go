package auth

// https://fusionauth.io/docs/v1/tech/client-libraries/go/

import (
	"fa-middleware/config"
	"fa-middleware/models"
	"fmt"

	"github.com/FusionAuth/go-client/pkg/fusionauth"
)

// Login logs in the user using the FusionAuth Go client library
func Login(conf config.Config, fa *fusionauth.FusionAuthClient, oauthState models.OauthState) (user fusionauth.User, jwt string, err error) {
	// TODO: Use https://fusionauth.io/docs/v1/tech/apis/jwt/#retrieve-refresh-tokens
	// TODO: to try and retrieve a refresh token and compare it to an HttpOnly
	// TODO: cookie that contains a refresh token from the gin context
	// TODO: so that we can automatically grant the user a new JWT based on
	// TODO: their refresh token

	token, oauthError, err := fa.ExchangeOAuthCodeForAccessTokenUsingPKCE(
		oauthState.Code,
		conf.FusionAuthOauthClientID,
		conf.FusionAuthOauthClientSecret,
		conf.FusionAuthOauthRedirectURL,
		oauthState.Verifier,
	)

	if err != nil {
		return user, "", fmt.Errorf(
			"failed to exchange oauth code for access token via pkce: %v",
			err.Error(),
		)
	}

	if oauthError != nil {
		return user, "", fmt.Errorf(
			"failed to exchange oauth code for access token via pkce oauth error: %v",
			oauthError,
		)
	}

	user, err = GetUserByJWT(conf, token.AccessToken)
	// userResp, errs, err := fa.RetrieveUserUsingJWT(token.AccessToken)
	// userResp, errs, err := fa.RetrieveUserInfoFromAccessToken(token.AccessToken)
	if err != nil {
		return user, "", fmt.Errorf(
			"failed to retrieve user by jwt: %v",
			err.Error(),
		)
	}

	// log.Printf("%v", userResp.User.Data)

	return user, token.AccessToken, nil
}

func GetUserByJWT(conf config.Config, jwt string) (user fusionauth.User, err error) {
	userResp, errs, err := conf.FusionAuthClient.RetrieveUserUsingJWT(jwt)
	// userResp, errs, err := fa.RetrieveUserInfoFromAccessToken(token.AccessToken)
	if err != nil {
		return user, fmt.Errorf(
			"failed to retrieve user by token: %v",
			err.Error(),
		)
	}

	if errs != nil {
		if errs.Present() {
			return user, fmt.Errorf(
				"failed to retrieve user by token due to errors: %v",
				errs,
			)
		}

		return user, fmt.Errorf(
			"no errors were present while trying to retrieve user by token: %v",
			errs,
		)
	}

	return userResp.User, nil
}
