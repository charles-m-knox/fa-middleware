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
}

type UserData struct {
	UserID           string
	AppID            string
	TenantID         string
	StripeCustomerID string
	Field            string
	Value            string
	UpdatedAt        int64
}
