package payments

import (
	"fa-middleware/auth"
	"fa-middleware/config"
	"fa-middleware/models"

	"fmt"
	"log"
	"strings"
	"time"

	"github.com/FusionAuth/go-client/pkg/fusionauth"
	"github.com/gin-gonic/gin"
	"github.com/stripe/stripe-go/v72"
	"github.com/stripe/stripe-go/v72/client"
)

const (
	CacheExpirationSeconds = 60
	StripeCustomerIDField  = "stripeCustomerID"
)

// CachedUser is the struct that is responsible for what data gets associated
// with Stripe subscription check result caches.
type CachedUser struct {
	CacheTime  time.Time
	Subscribed bool
}

var SubscribedUserCache map[string]CachedUser

// InitializeSubscribedUserCache should be called once at the beginning of
// the program so that the cache map can be initialized.
func InitializeSubscribedUserCache() {
	SubscribedUserCache = make(map[string]CachedUser)
}

// getCustomerProductCacheStr simply builds a value that pairs
// a Stripe customer ID with the product ID as a string. This value
// is a string that gets put into the SubscribedUserCache as the key,
// and the value is a CachedUser (struct).
//
// Example: cus_J83zKLOHeJS4kC_prod_J7bo97LpdukduC
func getCustomerProductCacheStr(stripeCustomerID string, stripeProductID string) string {
	return fmt.Sprintf("%v_%v", stripeCustomerID, stripeProductID)
}

// IsUserCacheExpired checks if the cached value (from checking the Stripe API
// to see if a customer ID has a subscription to a specific product ID) is
// not expired, based on whether enough time has elapsed since the value was
// cached.
//
// See CacheExpirationSeconds
//
// TODO: Configurable CacheExpirationSeconds instead of hardcode
func (cachedUser *CachedUser) IsUserCacheExpired() bool {
	return time.Now().After(
		cachedUser.CacheTime.Add(
			time.Second * CacheExpirationSeconds,
		),
	)
}

// AddUserToCache adds a Stripe customer & product check result to the
// in-memory cache with the current time as the cache start time.
func AddUserToCache(stripeCustID string, stripeProductID string, subState bool) {
	cacheStr := getCustomerProductCacheStr(stripeCustID, stripeProductID)
	SubscribedUserCache[cacheStr] = CachedUser{
		CacheTime:  time.Now(),
		Subscribed: subState,
	}
}

// IsUserSubscribedCached checks if a user is subscribed via cache
func IsUserSubscribedCached(stripeCustomerID string, stripeProductID string) (bool, bool) {
	cacheStr := getCustomerProductCacheStr(stripeCustomerID, stripeProductID)
	cachedUser, ok := SubscribedUserCache[cacheStr]
	cacheExpired := cachedUser.IsUserCacheExpired()
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

// IsUserSubscribed checks if a user is subscribed to a given Stripe productID
// by first checking the in-memory cache, and if not, it will do an API call
// to Stripe directly.
//
// Cached results can take around 5-40ms for a complete API
// call, whereas a Stripe API call will take anywhere from 200-1000ms.
//
// TODO: The default expiration time for a cached entry is currently hardcoded
func IsUserSubscribed(conf config.App, user fusionauth.User, productID string) (bool, error) {
	sc := &client.API{}
	sc.Init(conf.Stripe.SecretKey, nil)

	existingID := user.Data[StripeCustomerIDField].(string)
	if existingID == "" {
		log.Printf("user %v is has no customer id", user.Id)
		return false, nil
	}

	cachedSub, cacheExpired := IsUserSubscribedCached(existingID, productID)
	if !cacheExpired {
		return cachedSub, nil
	}

	// query stripe to find the user
	params := &stripe.CustomerParams{}
	params.AddExpand("subscriptions")
	customer, err := sc.Customers.Get(existingID, params)
	if err != nil {
		return false, fmt.Errorf(
			"failed to get customer id %v: %v",
			existingID,
			err.Error(),
		)
	}
	if customer.ID != existingID {
		return false, fmt.Errorf(
			"customer id %v mismatched stripe customer id %v",
			existingID,
			customer.ID,
		)
	}
	for _, sub := range customer.Subscriptions.Data {
		if sub.Plan.Product.ID == productID {
			isActive := sub.Status == stripe.SubscriptionStatusActive
			AddUserToCache(
				existingID,
				productID,
				isActive,
			)
			return isActive, nil
		}
	}
	AddUserToCache(existingID, productID, false)
	return false, nil
}

// PropagateUserToStripe pushes a user to Stripe via the Stripe API, this is
// important because it returns a customerID that is our only correlation
// between Stripe and FusionAuth users. Email is the second most reliable
// correlation, but that can change as well.
//
// TODO: Set user ID and other metadata after propagation to Stripe
func PropagateUserToStripe(app config.App, user fusionauth.User) (custID string, err error) {
	sc := &client.API{}
	sc.Init(app.Stripe.SecretKey, nil)

	existingID := user.Data[StripeCustomerIDField]
	if existingID != nil && existingID.(string) != "" {
		return existingID.(string), nil
	}

	// customer probably doesn't exist, so let's try to create a new one in stripe
	if existingID == nil || existingID.(string) == "" {
		log.Printf(
			"user %v customer id is not in fa user data; setting up next...",
			user.Id,
		)
		customer, err := sc.Customers.New(
			&stripe.CustomerParams{
				Email: &user.Email,
				Name:  &user.FullName,
				Phone: &user.MobilePhone,
			},
		)
		if err != nil {
			return "", fmt.Errorf("failed to create new customer: %v", err.Error())
		}

		// push the customer's ID to our db immediately!
		log.Printf("new customer id %v for user %v", customer.ID, user.Id)
		err = auth.SetUserData(app, user, "stripeCustomerID", customer.ID)
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
	return custID, nil
}

// GetProducts returns a list of products that are configured in one of your
// apps, with the intention of presenting the data to the frontend.
//
// https://stripe.com/docs/api/products/retrieve
func GetProducts(app config.App) (products []models.ProductSummary, err error) {
	sc := &client.API{}
	sc.Init(app.Stripe.SecretKey, nil)
	params := &stripe.ProductParams{}

	for _, stripeProduct := range app.Stripe.Products {
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

	app.StripeProductsFromAPI = products

	return products, nil
}

// CreateCheckoutSession uses the suggested code pattern from the Stripe API
// documentation - if there is an error, it will not set any gin response,
// but if it succeeds, it will set a 200 response with JSON data containing
// the Stripe session ID.
//
// Reference:
//
// https://stripe.com/docs/api/checkout/sessions/create
//
// Query params:
//
// - ids: a CSV list of price IDs, real values from Stripe
//
// - m: either "s" or "p" for subscription or one-time payment (no quotes)
//
// TODO: if no ids are specified, just put in all of them? or choose a default?
func CreateCheckoutSession(c *gin.Context, conf config.App, user fusionauth.User) error {
	sc := &client.API{}
	sc.Init(conf.Stripe.SecretKey, nil)

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
		SuccessURL:    stripe.String(conf.Stripe.PaymentSuccessURL),
		CancelURL:     stripe.String(conf.Stripe.PaymentCancelURL),
	}

	// populate the checkout with the provided price ids, if they exist
	// retrieve the form query for the product ids. Otherwise, add them all
	// TODO: add "default line item" in config
	csvPriceIDs := c.Query("ids")
	priceIDs := strings.Split(csvPriceIDs, ",")
	if csvPriceIDs == "" {
		for _, stripeProduct := range conf.Stripe.Products {
			priceIDs = append(priceIDs, stripeProduct.PriceIDs...)
		}
	}

	// priceMode must be either "s" for subscription or "p" for one-type payment
	priceMode := c.Query("m")

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
					params.LineItems = append(
						params.LineItems,
						&stripe.CheckoutSessionLineItemParams{
							Price:    stripe.String(queriedPriceID),
							Quantity: stripe.Int64(1),
						},
					)
					break
				}
			}
		}
	}

	session, err := sc.CheckoutSessions.New(params)
	if err != nil {
		return fmt.Errorf("session.new: %v", err.Error())
	}

	data := models.CreateCheckoutSessionResponse{
		SessionID: session.ID,
	}

	c.JSON(200, data)
	return nil
}
