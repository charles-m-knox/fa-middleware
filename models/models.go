package models

type OauthState struct {
	State    string `json:"state"`
	Code     string `json:"code"`
	Verifier string
}

type PostMutationBody struct {
	Domain string `json:"d"`
	JWT    string `json:"s"`
	Field  string `json:"f"`
	Value  string `json:"v"`
	Method string `json:"m"`
	Key    string `json:"k"`
}

type UserData struct {
	UserID    string
	AppID     string
	TenantID  string
	Field     string
	Value     string
	UpdatedAt int64
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

type SubscriberField struct {
	Field       string `yaml:"field"`
	FieldRegExp string `yaml:"fieldRegExp"`
	ProductID   string `yaml:"productId"`
}

type MutableFields struct {
	System         []string          `yaml:"system"`
	User           []string          `yaml:"user"`
	SubscriberOnly []SubscriberField `yaml:"subscriberOnly"`
}
