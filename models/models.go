package models

type OauthState struct {
	State    string `json:"state"`
	Code     string `json:"code"`
	Verifier string
}

type SubscriptionStatusCheckBody struct {
	UserID    string `json:"userId"`
	JWT       string `json:"jwt"`
	APIKey    string `json:"key"`
	ProductID string `json:"productId"`
}

type LoggedInResponse struct {
	LoggedIn     bool   `json:"loggedIn"`
	UserID       string `json:"userId"`
	UserEmail    string `json:"userEmail"`
	UserFullName string `json:"userFullName"`
}

type StripeProduct struct {
	ProductID string   `yaml:"productId"`
	PriceIDs  []string `yaml:"priceIds"`
}

type ProductPrice struct {
	ID                     string
	ProductID              string
	IsSubscription         bool
	RecurringInterval      string // day, week, month or year.
	RecurringIntervalCount int64  // For example, interval=month and interval_count=3 bills every 3 months.
	Price                  int64
	PriceDecimal           float64
	PriceStr               string
	Currency               string
	Description            string
}

type ProductSummary struct {
	ID          string
	Name        string
	Description string
	ImageURL    string
	Prices      []ProductPrice
}

type CreateCheckoutSessionResponse struct {
	SessionID string `json:"id"`
}
