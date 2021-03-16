package payments

import (
	"fa-middleware/auth"
	"fa-middleware/config"
	"fa-middleware/models"
	"fa-middleware/userdata"
	"regexp"
	"time"

	"log"
	"strings"

	"fmt"

	"github.com/FusionAuth/go-client/pkg/fusionauth"
	"github.com/gin-gonic/gin"
	"github.com/stripe/stripe-go/v72"
	"github.com/stripe/stripe-go/v72/client"
)

type CachedUser struct {
	CacheTime  time.Time
	Subscribed bool
}

var SubscribedUserCache map[string]CachedUser

// InitializeSubscribedUserCache should be called once at the beginning of
// the program
func InitializeSubscribedUserCache() {
	SubscribedUserCache = make(map[string]CachedUser)
}

func (cachedUser *CachedUser) IsUserCacheExpired() bool {
	return time.Now().After(cachedUser.CacheTime.Add(time.Second * 30))
}

func AddUserToCache(stripeCustomerID string, substate bool) {
	SubscribedUserCache[stripeCustomerID] = CachedUser{
		CacheTime:  time.Now(),
		Subscribed: substate,
	}
}

// IsUserSubscribedCached checks if a user is subscribed via cache
func IsUserSubscribedCached(stripeCustomerID string) (subbed bool, cacheExpired bool) {
	cachedUser, ok := SubscribedUserCache[stripeCustomerID]
	cacheExpired = cachedUser.IsUserCacheExpired()
	if !ok || cacheExpired {
		// the user's cached value has expired, or the user has not yet been
		// cached at all, so we need to hit the stripe API
		return false, cacheExpired
	}

	// at this point the user has been cached previously, AND the cache value
	// has not expired yet, so it is valid to assume that cached value is
	// correct
	return cachedUser.Subscribed, false
}

func IsUserSubscribed(conf config.Config, user fusionauth.User, productID string) (bool, error) {
	sc := &client.API{}
	sc.Init(conf.StripeSecretKey, nil)

	existingStripeCustomerID, err := userdata.GetValueForUser(conf, user, "stripe_customer_id")
	if err != nil {
		return false, fmt.Errorf("failed to get customer id from local db: %v", err.Error())
	}

	subscribedViaCache, cacheExpired := IsUserSubscribedCached(existingStripeCustomerID)
	if subscribedViaCache && !cacheExpired {
		return true, nil
	}

	// query stripe to find the user
	params := &stripe.CustomerParams{}
	params.AddExpand("subscriptions")
	customer, err := sc.Customers.Get(existingStripeCustomerID, params)
	if err != nil {
		return false, fmt.Errorf(
			"failed to get customer id %v: %v",
			existingStripeCustomerID,
			err.Error(),
		)
	}
	if customer.ID != existingStripeCustomerID {
		return false, fmt.Errorf(
			"customer id %v mismatched stripe customer id %v",
			existingStripeCustomerID,
			customer.ID,
		)
	}
	for _, sub := range customer.Subscriptions.Data {
		if sub.Plan.Product.ID == productID {
			AddUserToCache(existingStripeCustomerID, sub.Status == stripe.SubscriptionStatusActive)
			return sub.Status == stripe.SubscriptionStatusActive, nil
		}
	}
	AddUserToCache(existingStripeCustomerID, false)
	return false, nil
}

func PropagateUserToStripe(conf config.Config, user fusionauth.User) (customerID string, err error) {
	sc := &client.API{}
	sc.Init(conf.StripeSecretKey, nil)

	existingStripeCustomerID, err := userdata.GetValueForUser(conf, user, "stripe_customer_id")
	if err != nil {
		return "", fmt.Errorf("failed to get customer id from local db: %v", err.Error())
	}

	// customer probably doesn't exist, so let's try to create a new one in stripe
	if existingStripeCustomerID == "" {
		customer, err := sc.Customers.New(&stripe.CustomerParams{
			Email: &user.Email,
			Name:  &user.FullName,
			Phone: &user.MobilePhone,
		})
		if err != nil {
			return "", fmt.Errorf("failed to create new customer: %v", err.Error())
		}

		// push the customer's ID to database immediately!
		log.Printf("new customer id: %v", customer.ID)
		err = userdata.SetValueForUser(conf, user, "stripe_customer_id", customer.ID)
		if err != nil {
			return customer.ID, fmt.Errorf(
				"failed to push customer id %v to database: %v",
				customer.ID,
				err.Error(),
			)
		}

		return customer.ID, nil
	}

	// now the customer DOES exist already, so we don't have to propagate them to Stripe
	// TODO: validate that the customer's email matches stripe email, and update if needed
	return customerID, nil
}

// https://stripe.com/docs/api/products/retrieve
func GetProducts(conf config.Config) (products []models.ProductSummary, err error) {
	sc := &client.API{}
	sc.Init(conf.StripeSecretKey, nil)
	params := &stripe.ProductParams{}
	for _, stripeProduct := range conf.StripeProducts {
		product, err := sc.Products.Get(stripeProduct.ProductID, params)
		if err != nil {
			return products, fmt.Errorf(
				"failed to get product from stripe by id %v: %v",
				stripeProduct.ProductID,
				err.Error(),
			)
		}
		// validate that the metadata for the product matches
		// TODO: re-enable if needed
		// productAppID, ok := product.Metadata["appId"]
		// if !ok || productAppID != conf.FusionAuthAppID {
		// 	log.Printf(
		// 		"appId=%v from stripe not defined or mismatched from configured app id=%v for product id %v",
		// 		productAppID,
		// 		conf.FusionAuthAppID,
		// 		stripeProduct.ProductID,
		// 	)
		// 	continue
		// }
		// productTenantID, ok := product.Metadata["tenantId"]
		// if !ok || productTenantID != conf.FusionAuthTenantID {
		// 	log.Printf(
		// 		"tenantId=%v from stripe not defined or mismatched from configured tenant id=%v for product id %v",
		// 		productTenantID,
		// 		conf.FusionAuthTenantID,
		// 		stripeProduct.ProductID,
		// 	)
		// 	continue
		// }
		if !product.Active {
			continue
		}
		imageURL := ""
		if len(product.Images) > 0 {
			imageURL = product.Images[0]
		}

		// get all the prices now
		productPrices := []models.ProductPrice{}
		for _, priceID := range stripeProduct.PriceIDs {
			stripePrice, err := sc.Prices.Get(priceID, &stripe.PriceParams{})
			if err != nil {
				log.Printf(
					"failed to get price id %v for product id %v: %v",
					priceID,
					stripeProduct.ProductID,
					err.Error(),
				)
			}
			if !stripePrice.Active {
				continue
			}
			if stripePrice.Product == nil {
				log.Printf(
					"stripe price %v doesn't have corresponding product, skipping",
					stripePrice.ID,
				)
				continue
			}
			if stripePrice.Product.ID != stripeProduct.ProductID {
				log.Printf(
					"price id %v and product id %v ?= %v mismatch, ignoring",
					stripePrice.ID,
					stripePrice.Product.ID,
					stripeProduct.ProductID,
				)
				continue
			}
			// the price has been validated; now add it to the list of prices
			recurringInterval := ""
			recurringIntervalCount := int64(0)
			isSubscription := false
			if stripePrice.Recurring != nil {
				recurringInterval = string(stripePrice.Recurring.Interval)
				recurringIntervalCount = stripePrice.Recurring.IntervalCount
				isSubscription = true
			}
			priceStr := fmt.Sprintf("%.2f", stripePrice.UnitAmountDecimal/100.0)
			productPrices = append(productPrices, models.ProductPrice{
				ID:                     stripePrice.ID,
				ProductID:              stripeProduct.ProductID,
				IsSubscription:         isSubscription,
				RecurringInterval:      recurringInterval,
				RecurringIntervalCount: recurringIntervalCount,
				Price:                  stripePrice.UnitAmount,
				PriceDecimal:           stripePrice.UnitAmountDecimal,
				PriceStr:               priceStr,
				Currency:               string(stripePrice.Currency),
				Description:            stripePrice.Nickname,
			})
		}
		products = append(products, models.ProductSummary{
			ID:          stripeProduct.ProductID,
			Name:        product.Name,
			Description: product.Description,
			ImageURL:    imageURL,
			Prices:      productPrices,
		})
	}

	conf.StripeProductsFromAPI = products

	return products, nil
}

type CreateCheckoutSessionResponse struct {
	SessionID string `json:"id"`
}

// https://stripe.com/docs/api/checkout/sessions/create
// query params:
// - ids=csv price IDs from stripe
// - m=either "s" or "p" for subscription or one-time payment (no quotes)
// TODO: if no ids are specified, just put in all of them? or choose a default?
func CreateCheckoutSession(c *gin.Context, conf config.Config, user fusionauth.User) error {
	sc := &client.API{}
	sc.Init(conf.StripeSecretKey, nil)
	// retrieve the products from stripe
	products, err := GetProducts(conf)
	if err != nil {
		return fmt.Errorf(
			"failed to retrieve products for checkout session: %v",
			err.Error(),
		)
	}
	params := &stripe.CheckoutSessionParams{
		PaymentMethodTypes: stripe.StringSlice([]string{
			"card",
		}),
		CustomerEmail: &user.Email,
		LineItems:     []*stripe.CheckoutSessionLineItemParams{},
		// Mode:       stripe.String(string(stripe.CheckoutSessionModePayment)),
		// SuccessURL: stripe.String(conf.FullDomainURL + "/pages/t/stripesuccess.html"),
		SuccessURL: stripe.String(conf.StripePaymentSuccessURL),
		// CancelURL:  stripe.String(conf.FullDomainURL + "/pages/t/stripecancel.html"),
		CancelURL: stripe.String(conf.StripePaymentCancelURL),
	}

	// populate the checkout with the provided price ids, if they exist
	// retrieve the form query for the product ids. Otherwise, add them all
	// TODO: add "default line item" in config
	csvPriceIDs := c.Query("ids")
	priceIDs := strings.Split(csvPriceIDs, ",")
	if csvPriceIDs == "" {
		for _, stripeProduct := range conf.StripeProducts {
			priceIDs = append(priceIDs, stripeProduct.PriceIDs...)
		}
	}
	priceMode := c.Query("m") // must be either "s" for subscription or "p" for one-type payment
	switch priceMode {
	case "p":
		params.Mode = stripe.String(string(stripe.CheckoutSessionModePayment))
	case "s":
		params.Mode = stripe.String(string(stripe.CheckoutSessionModeSubscription))
	default:
		return fmt.Errorf("priceMode query parameter was not set to either 'p' or 's'")
	}
	for _, product := range products {
		for _, price := range product.Prices {
			for _, queriedPriceID := range priceIDs {
				if queriedPriceID == price.ID {
					// we found a price that was requested by the URL that was entered,
					// so proceed to add it to the LineItems for the Stripe checkout.
					// But first, we have to ignore all prices that don't match the query parameter
					// for a subscription vs. a one-time payment
					if priceMode == "s" && price.RecurringInterval == "" {
						break
					}
					if priceMode == "m" && price.RecurringInterval != "" {
						break
					}
					params.LineItems = append(params.LineItems, &stripe.CheckoutSessionLineItemParams{
						Price:    stripe.String(queriedPriceID),
						Quantity: stripe.Int64(1),
					})
					break
				}
			}
		}
	}

	// session, err := session.New(params)
	session, err := sc.CheckoutSessions.New(params)
	if err != nil {
		return fmt.Errorf("session.New: %v", err.Error())
	}

	data := CreateCheckoutSessionResponse{
		SessionID: session.ID,
	}

	c.JSON(200, data)
	return nil
}

// IsFieldMutable tests if the desired field can be changed according to whether
// or not the mutation request has sufficient privileges - system, user, subscriber.
func IsFieldMutable(conf config.Config, mutation models.PostMutationBody) (bool, error) {
	if mutation.Key == conf.MutationKey {
		return true, nil
	}

	if mutation.JWT != "" {
		user, err := auth.GetUserByJWT(conf, mutation.JWT)
		if err != nil {
			return false, fmt.Errorf("failed to check user jwt during mutability check: %v", err.Error())
		}
		// check if the field is a system field
		for _, sysField := range conf.MutableFields.System {
			if mutation.Field == sysField {
				return false, nil
			}
			// check if regexp is defined and matches
			fieldRegExpMatch := false
			if sysField != "" {
				fieldRegExpMatch, err = regexp.Match(sysField, []byte(mutation.Field))
				if err != nil {
					log.Printf("regexp err, sys field %v: %v", mutation.Field, err.Error())
				}
			}
			if fieldRegExpMatch {
				return true, nil
			}
		}

		// check if the field is a user-only field
		for _, userField := range conf.MutableFields.User {
			if mutation.Field == userField {
				return true, nil
			}
			// check if regexp is defined and matches
			fieldRegExpMatch := false
			if userField != "" {
				fieldRegExpMatch, err = regexp.Match(userField, []byte(mutation.Field))
				if err != nil {
					log.Printf("regexp err, user field %v: %v", mutation.Field, err.Error())
				}
			}
			if fieldRegExpMatch {
				return true, nil
			}
		}

		// check if the field is a subscriber-only field
		for _, subscriberField := range conf.MutableFields.SubscriberOnly {
			// check if regexp is defined and matches
			fieldRegExpMatch := false
			if subscriberField.FieldRegExp != "" {
				fieldRegExpMatch, err = regexp.Match(subscriberField.FieldRegExp, []byte(mutation.Field))
				if err != nil {
					log.Printf("regexp err, sub field %v: %v", mutation.Field, err.Error())
				}
			}
			if mutation.Field == subscriberField.Field || fieldRegExpMatch {
				// check if the user is a stripe subscriber
				subbed, err := IsUserSubscribed(conf, user, subscriberField.ProductID)
				if err != nil {
					return false, fmt.Errorf(
						"failed to check if user %v is subscribed to modify field %v for product id %v: %v",
						user.Id,
						mutation.Field,
						subscriberField.ProductID,
						err.Error(),
					)
				}
				return subbed, nil
			}
		}
	}

	return false, nil
}
